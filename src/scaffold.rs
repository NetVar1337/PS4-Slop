//! Self-contained, buildable diagnostic payload projects.
use crate::{Result, artifacts::ArtifactStore};
use anyhow::ensure;
use serde_json::{Value, json};

pub const FILES: &[(&str, &str)] = &[
    (
        "include/internals/runtime.hpp",
        include_str!("../internals/include/internals/runtime.hpp"),
    ),
    (
        "include/internals/verify.hpp",
        include_str!("../internals/include/internals/verify.hpp"),
    ),
    (
        "include/internals/memory.hpp",
        include_str!("../internals/include/internals/memory.hpp"),
    ),
    (
        "include/internals/ue4.hpp",
        include_str!("../internals/include/internals/ue4.hpp"),
    ),
    (
        "include/internals/source.hpp",
        include_str!("../internals/include/internals/source.hpp"),
    ),
    (
        "include/internals/hook.hpp",
        include_str!("../internals/include/internals/hook.hpp"),
    ),
    (
        "include/internals/platform.hpp",
        include_str!("../internals/include/internals/platform.hpp"),
    ),
    ("runtime.cpp", include_str!("../internals/src/runtime.cpp")),
    ("build.py", include_str!("../templates/payload/build.py")),
    (
        "src/payload.cpp",
        include_str!("../templates/payload/payload.cpp"),
    ),
    (
        "src/generated/target.hpp",
        include_str!("../templates/payload/target.hpp"),
    ),
    (
        "src/generated/engine_config.hpp",
        include_str!("../templates/payload/engine_config.hpp"),
    ),
    (
        "tests/host_smoke.cpp",
        include_str!("../templates/payload/host_smoke.cpp"),
    ),
];
pub fn create(store: &ArtifactStore, name: &str, engine: &str) -> Result<Value> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.as_bytes()[0].is_ascii_alphabetic()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "Invalid scaffold name"
    );
    ensure!(
        ["generic", "source", "unreal"].contains(&engine),
        "Unknown engine"
    );
    let relative = format!("projects/{name}");
    let folder = store.new_path(&relative)?;
    ensure!(!folder.exists(), "Project already exists");
    std::fs::create_dir_all(&folder)?;
    for (path, content) in FILES {
        let path = folder.join(path);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, content)?;
    }
    let source_commit = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    let python = if cfg!(windows) { "python" } else { "python3" };
    let recipe = json!({"sdk":"payload","source_commit":source_commit,"commands":[[python,"build.py"]],"output":"build/payload.elf","environment":{},"timeout_seconds":300});
    std::fs::write(
        folder.join("recipe.json"),
        serde_json::to_vec_pretty(&recipe)?,
    )?;
    let descriptor = json!({"format":"ps4wb-scaffold-v1","engine":engine,"rpc_version":1,"staging":"immediate","payload":"build/payload.elf","generated_directory":"src/generated","hardware_verified":false});
    std::fs::write(
        folder.join("workbench.json"),
        serde_json::to_vec_pretty(&descriptor)?,
    )?;
    std::fs::write(folder.join(".gitignore"), "build/\n__pycache__/\n")?;
    std::fs::write(
        folder.join("README.md"),
        format!(
            "# {name}\n\nRun `{python} build.py --host-test` for the offline lifecycle smoke test.\nRun `{python} build.py` with OO_PS4_TOOLCHAIN set to build build/payload.elf.\n\nEngine: {engine}. Target checks are initially empty and stay unavailable.\nInstall generated evidence with project_install. No build deploys to a console.\nSupply a mapping-aware MemoryReader on the payload thread before engine enumeration.\nRPC 7 negotiates protocol v1; RPC 6 telemetry index 0 is verification and index 1 object count.\n"
        ),
    )?;
    Ok(
        json!({"project":relative,"recipe":format!("{relative}/recipe.json"),"ready_to_build":true,"hardware_verified":false,"engine":engine,"source_commit":source_commit,"host_test":[python,"build.py","--host-test"]}),
    )
}
