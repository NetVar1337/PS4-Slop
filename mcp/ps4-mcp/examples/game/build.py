"""Build diagnostics with explicit argv; no injection or console connections."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def validate_generated(root):
    """Refuse a partial or modified generated set before producing an ELF."""
    generated = root / "src/generated"
    manifest_path = generated / "manifest.json"
    install_path = generated / "install.json"
    if not manifest_path.exists() and not install_path.exists():
        return  # Fresh, intentionally unconfigured scaffold.
    if not manifest_path.is_file() or not install_path.is_file():
        raise SystemExit("Generated inputs are incomplete; rerun project_install")
    try:
        manifest = json.loads(manifest_path.read_text())
        install = json.loads(install_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Invalid generated install manifest: {error}") from error
    if install.get("format") != "ps4wb-installed-v1" or install.get("module_sha256") != manifest.get("module_sha256"):
        raise SystemExit("Generated inputs belong to different builds; rerun project_install")
    records = install.get("files")
    if not isinstance(records, list) or len(records) > 32:
        raise SystemExit("Invalid generated file list; rerun project_install")
    for record in records:
        if not isinstance(record, dict):
            raise SystemExit("Invalid generated file record; rerun project_install")
        name = record.get("file", "")
        if not name or Path(name).name != name:
            raise SystemExit("Invalid generated file name in install manifest")
        path = generated / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record.get("sha256"):
            raise SystemExit(f"Generated input changed or incomplete: {name}; rerun project_install")


def compiler(name, fallback):
    configured = os.environ.get(name)
    if configured:
        return configured
    found = shutil.which(fallback)
    if found:
        return found
    windows = Path(r"C:\Program Files\LLVM\bin") / (fallback + ".exe")
    if windows.is_file():
        return str(windows)
    raise SystemExit(f"Missing {fallback}; set {name}")


def run(argv):
    subprocess.run([str(value) for value in argv], check=True, timeout=300)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-test", action="store_true")
    parser.add_argument("--check-generated", action="store_true", help="validate generated inputs and exit")
    parser.add_argument("--engine", choices=["generic", "source", "unreal"], default="generic",
                        help="engine feature pack define (PS4WB_ENGINE_SOURCE/PS4WB_ENGINE_UNREAL)")
    parser.add_argument("--sdk", default=os.environ.get("OO_PS4_TOOLCHAIN"))
    parser.add_argument("--output", default="build/payload.elf", help="payload path relative to the project")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    validate_generated(root)
    if args.check_generated:
        return
    build = root / "build"
    build.mkdir(exist_ok=True)
    cxx = compiler("CXX", "clang++")
    engine_define = {"source": "-DPS4WB_ENGINE_SOURCE", "unreal": "-DPS4WB_ENGINE_UNREAL"}.get(args.engine)
    common = ["-std=c++17", "-O2", "-Wall", "-Wextra", "-I" + str(root / "include"), "-I" + str(root / "src")]
    if engine_define:
        common.append(engine_define)
    sources = [root / "src/payload.cpp", root / "runtime.cpp"]
    runtime_kit = (root / "src/features.hpp").is_file()
    if runtime_kit:
        sources.extend([root / "draw.cpp", root / "input.cpp"])
    if args.host_test:
        output = build / ("host-smoke.exe" if os.name == "nt" else "host-smoke")
        run([cxx, *common, "-DPS4WB_HOST_TEST", *sources, root / "tests/host_smoke.cpp", "-o", output])
        run([output])
        return
    sdk = Path(args.sdk or Path.home() / ".local/openorbis-ps4-toolchain").resolve()
    for needed in ("link.x", "lib/crt1.o", "include"):
        if not (sdk / needed).exists():
            raise SystemExit(f"Incomplete OpenOrbis SDK: {sdk / needed}")
    payload_output = (root / args.output).resolve()
    if payload_output == root or root not in payload_output.parents:
        raise SystemExit("Payload output must stay inside the project")
    payload_output.parent.mkdir(parents=True, exist_ok=True)
    flags = ["--target=x86_64-pc-freebsd12-elf", "-fPIC", "-funwind-tables", "-fno-exceptions", "-fno-rtti", "-D__PS4__", "-D_BSD_SOURCE", "-isysroot", sdk, "-isystem", sdk / "include", "-isystem", sdk / "include/c++/v1"]
    objects = []
    for source in sources:
        output = build / (source.stem + ".o")
        run([cxx, *common, *flags, "-c", source, "-o", output])
        objects.append(output)
    libraries = ["-lkernel", "-lc"]
    if runtime_kit:
        libraries.extend(["-lScePad", "-lSceUserService"])
    run([compiler("LLD", "ld.lld"), "-m", "elf_x86_64", "-pie", "--script", sdk / "link.x", "--eh-frame-hdr", "-o", payload_output, *objects, "-L" + str(sdk / "lib"), *libraries, sdk / "lib/crt1.o"])


if __name__ == "__main__":
    main()
