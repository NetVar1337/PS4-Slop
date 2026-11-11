// app/src-tauri/src/lib.rs
//
// supervises the c++ engine sidecar and tells the web ui where to reach it
// the engine is a separate process because the c++ tree links the static crt
// and rust links the dynamic one, loopback costs a json round trip and buys
// crash isolation, the supervisor (supervisor.rs) respawns it when it dies

mod engine_log;
mod supervisor;

use engine_log::EngineLog;
use std::path::PathBuf;
use std::sync::Arc;
use supervisor::{Endpoint, Engine, Status, HANDSHAKE_DEADLINE};
use tauri::{AppHandle, Manager, RunEvent, State, WindowEvent};

/// blocks until the current engine has a port, through a restart in progress;
/// errors only once the supervisor gave up or the handshake deadline passes
#[tauri::command]
async fn engine_endpoint(app: AppHandle) -> Result<Endpoint, String> {
    // the wait can take minutes, keep it off the ipc thread
    tauri::async_runtime::spawn_blocking(move || app.state::<Engine>().wait(HANDSHAKE_DEADLINE))
        .await
        .map_err(|e| format!("engine wait failed: {e}"))?
}

/// the supervisor's handshake deadline, the ui health gate uses the same one
#[tauri::command]
fn startup_deadline_ms() -> u64 {
    HANDSHAKE_DEADLINE.as_millis() as u64
}

#[tauri::command]
fn engine_status(engine: State<'_, Engine>) -> Status {
    engine.status()
}

/// re-arms a supervisor that gave up, or cycles a running engine
#[tauri::command]
fn restart_engine(app: AppHandle) -> Result<(), String> {
    supervisor::request_restart(&app)
}

/// where the engine binary lives: next to us once installed; debug builds
/// check the cmake tree first on purpose, tauri copies the resource engine at
/// cargo build time and a stale copy cost an afternoon of debugging once
fn sidecar_path(app: &AppHandle) -> Result<PathBuf, String> {
    const NAME: &str = "reverse-slop-engine.exe";

    let installed = || -> Option<PathBuf> {
        if let Ok(dir) = app.path().resource_dir() {
            let bundled = dir.join("engine").join(NAME);
            if bundled.is_file() {
                return Some(bundled);
            }
        }
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        [dir.join(NAME), dir.join("engine").join(NAME)]
            .into_iter()
            .find(|c| c.is_file())
    };

    #[cfg(debug_assertions)]
    let found = dev_tree(NAME).or_else(installed);
    #[cfg(not(debug_assertions))]
    let found = installed();

    found.ok_or_else(|| {
        format!("{NAME} not found, build it with tools/build.ps1 (SLOP_BUILD_ENGINE=ON)")
    })
}

/// the cmake output tree, compiled into debug builds only so release binaries
/// never carry or probe a build-machine path
#[cfg(debug_assertions)]
fn dev_tree(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../build/src/engine")
        .join(name);
    p.is_file().then(|| p.canonicalize().unwrap_or(p))
}

/// kill on close job object: the engine exits cleanly through the graceful
/// stop or its parent-pid watch, this is the backstop that guarantees a wedged
/// engine never outlives the ui and keeps holding the port and console sockets
#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// the handle is leaked deliberately on success: it must outlive every
    /// scope in this process, because closing it is exactly what kills the engine
    pub fn adopt(child: &std::process::Child) -> Result<(), String> {
        // SAFETY: plain win32 calls on handles we own, every failure is checked
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err("CreateJobObject failed".into());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                CloseHandle(handle);
                return Err("SetInformationJobObject failed".into());
            }
            if AssignProcessToJobObject(handle, child.as_raw_handle() as HANDLE) == 0 {
                CloseHandle(handle);
                return Err("AssignProcessToJobObject failed".into());
            }
        }
        Ok(())
    }
}

/// panics in the ui process go to the engine log too, release builds have no
/// console to print them on
fn install_panic_hook(log: Arc<EngineLog>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log.try_line("ui-panic", &info.to_string());
        previous(info);
    }));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let log = Arc::new(EngineLog::default_location());
    install_panic_hook(Arc::clone(&log));

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Engine::new(Arc::clone(&log)))
        .invoke_handler(tauri::generate_handler![
            engine_endpoint,
            startup_deadline_ms,
            engine_status,
            restart_engine
        ])
        .setup(|app| {
            // the devtools toggle permission exists only in debug builds, release
            // builds are compiled without devtools at all
            #[cfg(debug_assertions)]
            app.add_capability(
                tauri::ipc::CapabilityBuilder::new("debug-devtools")
                    .window("main")
                    .permission("core:webview:allow-internal-toggle-devtools"),
            )?;

            let handle = app.handle().clone();
            let path = sidecar_path(&handle);
            std::thread::Builder::new()
                .name("engine-supervisor".into())
                .spawn(move || supervisor::run(handle, path))?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // hide now and stop the engine off the event loop, the window
                // thread never blocks on the engine's teardown
                api.prevent_close();
                let _ = window.hide();
                let app = window.app_handle().clone();
                std::thread::spawn(move || {
                    supervisor::shutdown(&app);
                    app.exit(0);
                });
            }
        })
        .build(tauri::generate_context!());

    let app = match app {
        Ok(app) => app,
        Err(e) => {
            log.line("supervisor", &format!("ui failed to start: {e}"));
            std::process::exit(1);
        }
    };

    app.run(|handle, event| {
        // exits that skip CloseRequested (session end, app.exit from elsewhere)
        // still stop the engine; no window is left to block by now, and this is
        // a no-op when the close path already did it
        if let RunEvent::Exit = event {
            supervisor::shutdown(handle);
        }
    });
}
