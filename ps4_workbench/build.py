"""Bounded local argv builds and content-addressed source/output evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from .config import WorkbenchError


def source_snapshot(repo):
    files = {}
    total = 0
    for current, directories, names in os.walk(repo, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in {'.git', 'build', 'target', '__pycache__', '.venv'} and not (Path(current) / name).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            relative = path.relative_to(repo)
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in {'.h', '.hpp', '.c', '.cpp', '.py', '.json', '.cmake'} and path.name != 'Makefile':
                continue
            if path.name == 'workbench.lock.json':
                continue
            size = path.stat().st_size
            total += size
            if len(files) >= 10000 or total > 512 * 1024 * 1024:
                raise WorkbenchError('Source snapshot exceeds budget')
            files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {'sha256': digest, 'files': files}


def build(repo, argv, payload, timeout: float = 600, max_log=1024 * 1024):
    repo = Path(repo).resolve(strict=True)
    output = (repo / payload).resolve()
    if not output.is_relative_to(repo) or output == repo:
        raise WorkbenchError('Build output escapes repository')
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a and '\0' not in a for a in argv):
        raise WorkbenchError('Build command must be a nonempty JSON argv array')
    snapshot = source_snapshot(repo)
    # Keep old outputs as evidence; a failed/no-op build cannot reuse one.
    if output.exists():
        previous = hashlib.sha256(output.read_bytes()).hexdigest()
        archive = (repo / 'build' / 'archive' / (previous + '.elf')).resolve()
        if not archive.is_relative_to(repo):
            raise WorkbenchError('Build archive escapes repository')
        archive.parent.mkdir(parents=True, exist_ok=True)
        os.replace(output, archive)
    logs = bytearray()
    overflow = threading.Event()
    try:
        process = subprocess.Popen(argv, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=os.name != 'nt', creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
    except OSError as error:
        raise WorkbenchError(f'Cannot start build: {error}') from error
    stdout = process.stdout
    if stdout is None:
        raise WorkbenchError('Cannot capture build output')

    def read():
        while True:
            block = stdout.read(4096)
            if not block:
                break
            room = max_log - len(logs)
            logs.extend(block[:max(0, room)])
            if len(block) > room:
                overflow.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    exceeded = False
    while process.poll() is None:
        if overflow.is_set() or time.monotonic() > deadline:
            exceeded = True
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=10)
            else:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
            process.kill()
            break
        time.sleep(0.02)
    process.wait(timeout=10)
    reader.join(timeout=5)
    if not reader.is_alive():
        stdout.close()
    if reader.is_alive():
        raise WorkbenchError('Build left stdout open; detached children are unsupported')
    log_path = (repo / 'build' / 'workbench-build.log').resolve()
    if not log_path.is_relative_to(repo):
        raise WorkbenchError('Build log escapes repository')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(logs)
    if exceeded or overflow.is_set() or process.returncode:
        raise WorkbenchError(f'Build failed or exceeded bounds; see {log_path}')
    if not output.is_file() or not output.resolve().is_relative_to(repo):
        raise WorkbenchError('Build did not produce a fresh contained payload')
    content = output.read_bytes()
    if len(content) < 64 or content[:7] != b'\x7fELF\x02\x01\x01' or int.from_bytes(content[16:18], 'little') != 3 or int.from_bytes(content[18:20], 'little') != 62:
        raise WorkbenchError('Build output is not a little-endian x86-64 ET_DYN payload')
    if source_snapshot(repo)['sha256'] != snapshot['sha256']:
        raise WorkbenchError('Source changed during build; output provenance is uncertain')
    evidence = {'format': 'ps4wb-build-lock-v1', 'argv': argv, 'source': snapshot,
                'payload': {'path': str(output), 'sha256': hashlib.sha256(content).hexdigest()},
                'log': str(log_path), 'hardware_verified': False}
    (repo / 'workbench.lock.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    return evidence
