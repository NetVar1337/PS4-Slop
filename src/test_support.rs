use std::path::{Path, PathBuf};
pub fn compiler() -> PathBuf {
    if let Some(value) = std::env::var_os("CXX") {
        return value.into();
    }
    if let Some(path) = crate::development::which("clang++", std::env::var_os("PATH").as_ref()) {
        return path;
    }
    if cfg!(windows) {
        return r"C:\Program Files\LLVM\bin\clang++.exe".into();
    }
    "c++".into()
}
pub fn compile_run(directory: &Path, source: &str, runtime: bool) {
    compile_run_with_sources(directory, source, if runtime { &["runtime.cpp"] } else { &[] });
}

pub fn compile_run_with_sources(directory: &Path, source: &str, sources: &[&str]) {
    let path = directory.join("test.cpp");
    std::fs::write(&path, source).unwrap();
    let executable = directory.join(if cfg!(windows) { "test.exe" } else { "test" });
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = std::process::Command::new(compiler());
    command
        .args(["-std=c++17", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root.join("internals/include"))
        .arg("-I")
        .arg(directory)
        .arg(&path);
    for source in sources {
        command.arg(root.join("internals/src").join(source));
    }
    let output = command
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("Install a host C++17 compiler for generated-code integration checks");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = std::process::Command::new(executable).output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
