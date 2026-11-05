"""Start the native Rust stack (ps4debug fixture -> broker -> optional gdb-server) on loopback.

Build first: ``cargo build --release --features fixture --bins``.
Nothing here contacts a console; the fixture is a protocol server, not an emulator.
"""
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from tests.manual.run_installed_apps import elf_fixture

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "target" / "release"
WORKBENCH = RELEASE / ("ps4-workbench.exe" if os.name == "nt" else "ps4-workbench")
FIXTURE = RELEASE / ("ps4debug-fixture.exe" if os.name == "nt" else "ps4debug-fixture")
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
PID, THREAD = 71, 72


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_port(port, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Port {port} did not open")


class RustStack:
    """Context manager owning every spawned process and the temporary directory."""

    def __init__(self, debug_control=True):
        for binary in (WORKBENCH, FIXTURE):
            if not binary.exists():
                raise RuntimeError(f"Missing {binary}; run cargo build --release --features fixture --bins")
        self.temporary = tempfile.TemporaryDirectory(prefix="ps4-rust-stack-")
        self.directory = Path(self.temporary.name)
        self.processes = []
        self.handles = []
        self.debug_control = debug_control

    def spawn(self, arguments, **options):
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW, **options)
        self.processes.append(process)
        return process

    def workbench(self, *arguments):
        return [str(WORKBENCH), "--profile", str(self.profile), *arguments]

    def __enter__(self):
        self.image = self.directory / "fixture.elf"
        self.image.write_bytes(elf_fixture())
        fixture = self.spawn([str(FIXTURE), "--image", str(self.image), "--base", "0x400000", "--rip", "0x400100",
                              "--pid", str(PID), "--thread", str(THREAD)], stdout=subprocess.PIPE, text=True)
        debug_port = int(fixture.stdout.readline())
        settings = json.loads((ROOT / "profiles/ps4-1400.json").read_text(encoding="utf-8"))
        settings.update(host="127.0.0.1", artifact_directory="artifacts", qualification_file="qualification.local.json")
        settings["ports"]["debug"] = debug_port
        if self.debug_control:
            settings["permissions"]["debug_control"] = True
            settings["jailbreak"].update(installed_commit="a" * 40, hen_build="fixture-hen")
            settings["debugger"].update(expected_brand="ps4debug-NG by Pharaoh2k v1.3.4", payload_sha256="b" * 64)
        self.profile = self.directory / "profile.json"
        self.profile.write_text(json.dumps(settings), encoding="utf-8")
        if self.debug_control:
            evidence = self.directory / "evidence.txt"
            evidence.write_text("Loopback fixture only; not hardware evidence.\n", encoding="utf-8")
            subprocess.run(self.workbench("qualify", "--evidence", str(evidence), "--attest",
                                          "I_TESTED_THIS_EXACT_CONFIGURATION", "--approve", "debug_control"),
                           check=True, capture_output=True, creationflags=NO_WINDOW)
        self.token = self.directory / "broker-token.local"
        port = free_port()
        self.broker_log = (self.directory / "broker.log").open("w", encoding="utf-8")
        self.handles.append(self.broker_log)
        self.spawn(self.workbench("broker", "--port", str(port), "--token-file", str(self.token)),
                   stdout=self.broker_log, stderr=subprocess.STDOUT)
        wait_port(port)
        self.url = f"http://127.0.0.1:{port}"
        return self

    def gdb_server(self, allow_writes=False):
        port = free_port()
        arguments = self.workbench("gdb-server", "--broker", self.url, "--token-file", str(self.token),
                                   "--client-id", "ida-gdb", "--pid", str(PID), "--listen-address", "127.0.0.1",
                                   "--port", str(port))
        if allow_writes:
            arguments.append("--allow-writes")
        log = (self.directory / "gdb-server.log").open("w", encoding="utf-8")
        self.handles.append(log)
        self.spawn(arguments, stdout=log, stderr=subprocess.STDOUT)
        wait_port(port)
        return port

    def logs(self):
        return {path.name: path.read_text(errors="replace")[-8000:] for path in self.directory.glob("*.log")}

    def __exit__(self, *_):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            if process.stdout:
                process.stdout.close()
        for handle in self.handles:
            handle.close()
        self.temporary.cleanup()
