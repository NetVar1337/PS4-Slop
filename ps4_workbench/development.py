import hashlib
import json
import os
import shutil
import subprocess
import threading
import time

from .config import WorkbenchError, require_hash


SDKS = {
    "homebrew": {"name": "OpenOrbis", "environment": "OO_PS4_TOOLCHAIN",
                 "repository": "https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain",
                 "artifact_format": "pkg", "runtime_14_00_verified": False},
    "plugin": {"name": "GoldHEN Plugins SDK", "environment": "GOLDHEN_SDK",
               "repository": "https://github.com/GoldHEN/GoldHEN_Plugins_SDK",
               "artifact_format": "prx", "runtime_14_00_verified": False},
    "payload": {"name": "PS4 Payload SDK", "environment": "PS4_PAYLOAD_SDK",
                "repository": "https://github.com/ps4-payload-dev/sdk",
                "artifact_format": "elf", "runtime_14_00_verified": False,
                "warning": "Published SDK firmware list does not include 14.00; ELF must not use BinLoader"},
}


class Development:
    def __init__(self, profile, store):
        self.profile = profile
        self.store = store

    def status(self):
        return {"sdks": {name: {**settings, "configured_path": os.environ.get(settings["environment"])}
                         for name, settings in SDKS.items()},
                "executables": {name: shutil.which(name) for name in ("clang", "clang++", "cmake", "make", "ninja", "git")},
                "note": "Presence is not build or firmware compatibility verification; SDKs are not installed automatically"}

    def scaffold(self, kind, name):
        import re
        if kind not in SDKS or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", name):
            raise WorkbenchError("Choose homebrew/plugin/payload and a simple project name")
        folder = self.store.path("projects/" + name, must_exist=False)
        folder.mkdir(parents=True, exist_ok=False)
        recipe = {"sdk": kind, "source_commit": None, "commands": [], "output": None,
                  "environment": {}, "timeout_seconds": 120}
        (folder / "recipe.json").write_text(json.dumps(recipe, indent=2), encoding="utf-8")
        (folder / "README.md").write_text(
            f"# {name}\n\nSDK: {SDKS[kind]['name']}\nUpstream: {SDKS[kind]['repository']}\n\n"
            "Copy a matching upstream sample into this directory, pin its source commit, and supply\n"
            "the actual compiler/linker commands and relative output in recipe.json.\n"
            "This scaffold deliberately does not invent firmware offsets, SDK APIs, or linker scripts.\n"
            "Commands are argv arrays, never shell strings. Use native executables (not .bat/.cmd).\n"
            "Hash and locally approve the complete recipe before building through MCP.\n"
            "A successful build does not qualify its output for your console.\n", encoding="utf-8")
        return {"project": folder.relative_to(self.store.root).as_posix(), "recipe": "projects/" + name + "/recipe.json",
                "sdk": SDKS[kind], "ready_to_build": False, "next": "Add and pin an upstream SDK sample and complete recipe"}

    def build(self, recipe, sha256):
        qualification = self.profile.require("build")
        content = self.store.read(recipe, 65536)
        digest = hashlib.sha256(content).hexdigest()
        if digest != require_hash(sha256) or digest not in qualification.get("build_recipe_sha256_allowlist", []):
            raise WorkbenchError("Build recipe must match the locally approved SHA-256")
        settings = json.loads(content)
        if settings.get("sdk") not in SDKS:
            raise WorkbenchError("Unknown SDK recipe")
        import re
        if not re.fullmatch(r"[0-9a-f]{40}", settings.get("source_commit") or ""):
            raise WorkbenchError("Pin the sample/source commit in the recipe")
        commands = settings.get("commands")
        if not isinstance(commands, list) or not 1 <= len(commands) <= 16:
            raise WorkbenchError("Recipe needs 1 to 16 explicit argv commands")
        for command in commands:
            if not isinstance(command, list) or not command or any(not isinstance(part, str) or "\0" in part for part in command):
                raise WorkbenchError("Build commands must be nonempty string argv arrays")
        environment = settings.get("environment", {})
        if not isinstance(environment, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items()):
            raise WorkbenchError("Recipe environment must map strings to strings")
        from .config import require_integer
        timeout = require_integer(settings.get("timeout_seconds", 120), "build timeout", 1, 600)
        project = self.store.path(recipe).parent
        if not isinstance(settings.get("output"), str):
            raise WorkbenchError("Recipe needs a relative output path")
        output = (project / settings["output"]).resolve()
        if not output.is_relative_to(project) or output == project:
            raise WorkbenchError("Build output must stay inside project")
        if output.exists():
            raise WorkbenchError("Build output already exists; archive/remove it locally to prevent stale-output success")
        self.store.audit("build_intent", recipe=recipe, sha256=sha256)
        logs = bytearray()
        exceeded = threading.Event()
        deadline = time.monotonic() + timeout
        for command in commands:
            executable = shutil.which(command[0], path=environment.get("PATH", os.environ.get("PATH")))
            if not executable or executable.lower().endswith((".bat", ".cmd")):
                raise WorkbenchError("Build executable missing or batch file unsupported: " + command[0])
            process = subprocess.Popen([executable, *command[1:]], cwd=project,
                                       env={**os.environ, **environment}, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)

            def collect():
                try:
                    while True:
                        chunk = process.stdout.read(4096)
                        if not chunk:
                            break
                        available = self.profile.limit("log_bytes") - len(logs)
                        logs.extend(chunk[:available])
                        if len(chunk) > available:
                            exceeded.set()
                            process.kill()
                            break
                except OSError:
                    exceeded.set()

            reader = threading.Thread(target=collect, daemon=True)
            reader.start()
            timed_out = False
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
            reader.join(timeout=2)
            if reader.is_alive():
                exceeded.set()
            else:
                process.stdout.close()
            if process.returncode or timed_out or exceeded.is_set():
                log = self.store.save("build-log", bytes(logs), {"returncode": process.returncode, "timeout": timed_out})
                self.store.audit("build_failure", log=log)
                raise WorkbenchError(f"Build failed or exceeded bounds; see {log['path']}")
        if not output.is_file():
            raise WorkbenchError("Build succeeded but declared output does not exist")
        relative_output = output.relative_to(self.store.root).as_posix()
        artifact = self.store.save("build", self.store.read(relative_output),
                                   {"recipe_sha256": sha256, "sdk": settings["sdk"],
                                    "source_commit": settings["source_commit"], "hardware_verified": False})
        log = self.store.save("build-log", bytes(logs))
        self.store.audit("build_result", artifact=artifact, log=log)
        return {"artifact": artifact, "log": log, "deployed": False, "hardware_verified": False}
