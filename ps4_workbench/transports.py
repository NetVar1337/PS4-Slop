import ftplib
import hashlib
import io
import json
import posixpath
import re
import socket
import time
from contextlib import contextmanager

from .artifacts import utc_now
from .config import WorkbenchError, require_hash, require_integer


def remote_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
        raise WorkbenchError("Remote path must be absolute POSIX syntax")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise WorkbenchError("Control characters are forbidden in remote paths")
    if ".." in value.split("/"):
        raise WorkbenchError("Parent traversal is forbidden")
    return posixpath.normpath(value)


class ConsoleTransports:
    def __init__(self, profile, store):
        self.profile = profile
        self.store = store

    def status(self, probe=False):
        services = {}
        for service, port in self.profile.data["ports"].items():
            entry = {"port": port, "state": "configured_not_probed"}
            if probe and service != "payload":
                try:
                    with socket.create_connection((self.profile.host, port), self.profile.timeout):
                        entry["state"] = "tcp_reachable_not_protocol_verified"
                except OSError as error:
                    entry.update(state="unreachable", error=str(error))
            if service == "payload":
                entry["note"] = "Never probed: opening a loader connection can have side effects"
            services[service] = entry
        try:
            qualification = self.profile.qualification()
            compatibility = {"state": "user_attested_not_guaranteed", "recorded_at": qualification.get("recorded_at")}
        except WorkbenchError as error:
            compatibility = {"state": "hardware_unverified", "reason": str(error)}
        return {"host": self.profile.host, "firmware_claim": "14.00", "services": services,
                "compatibility": compatibility, "profile_sha256": self.profile.fingerprint}

    @contextmanager
    def ftp(self):
        client = ftplib.FTP(timeout=self.profile.timeout)
        client.trust_server_pasv_ipv4_address = False
        try:
            client.connect(self.profile.host, self.profile.data["ports"]["ftp"])
            client.login()
            client.set_pasv(True)
            yield client
        finally:
            client.close()

    def ftp_list(self, path="/"):
        path = remote_path(path)
        entries = []
        size = 0
        deadline = time.monotonic() + 60

        def collect(line):
            nonlocal size
            if time.monotonic() > deadline:
                raise WorkbenchError("FTP listing exceeded 60 second deadline")
            size += len(line.encode("utf-8"))
            if len(entries) >= self.profile.limit("list_entries") or size > self.profile.limit("transfer_bytes"):
                raise WorkbenchError("FTP listing exceeds limit; choose a narrower directory")
            entries.append(line)

        with self.ftp() as client:
            client.retrlines("LIST " + path, collect)
        return {"path": path, "listing": entries, "format": "server_supplied_LIST"}

    def _ftp_read(self, client, path, maximum=None):
        output = bytearray()
        deadline = time.monotonic() + 60

        def collect(chunk):
            if time.monotonic() > deadline:
                raise WorkbenchError("FTP download exceeded 60 second deadline")
            if len(output) + len(chunk) > (self.profile.limit("transfer_bytes") if maximum is None else maximum):
                raise WorkbenchError("FTP download exceeds transfer limit")
            output.extend(chunk)

        client.retrbinary("RETR " + path, collect)
        return bytes(output)

    def ftp_download(self, path):
        path = remote_path(path)
        with self.ftp() as client:
            content = self._ftp_read(client, path)
        return self.store.save("ftp", content, {"remote_path": path, "source": "FTP"})

    def ftp_extract(self, paths):
        if not isinstance(paths, list) or not 1 <= len(paths) <= 64:
            raise WorkbenchError("Select 1 to 64 explicit remote file paths")
        paths = [remote_path(path) for path in paths]
        if len(set(paths)) != len(paths):
            raise WorkbenchError("Duplicate extraction paths are not allowed")
        entries = []
        total = 0
        error_text = None
        deadline = time.monotonic() + 120
        try:
            with self.ftp() as client:
                for path in paths:
                    if time.monotonic() >= deadline:
                        raise WorkbenchError("Extraction exceeded 120-second deadline")
                    content = self._ftp_read(client, path, self.profile.limit("transfer_bytes") - total)
                    total += len(content)
                    entries.append(self.store.save("extracted", content, {"remote_path": path, "source": "FTP"}))
        except Exception as error:
            error_text = str(error)
        manifest = {"requested_paths": paths, "files": entries, "total_bytes": total,
                    "complete": len(entries) == len(paths), "error": error_text,
                    "note": "Raw FTP files, not decrypted/reconstructed executables; no automatic retry"}
        saved = self.store.save("extraction", json.dumps(manifest, indent=2).encode(), extension="json")
        return {"manifest": saved, **manifest}

    def ftp_upload(self, artifact, path, sha256):
        self.profile.require("ftp_upload")
        path = remote_path(path)
        roots = [remote_path(root) for root in self.profile.data["ftp_upload_roots"]]
        if not any(root != "/" and path.startswith(root + "/") for root in roots):
            raise WorkbenchError("FTP upload is outside the explicit upload roots")
        content = self.store.read(artifact)
        if hashlib.sha256(content).hexdigest() != require_hash(sha256):
            raise WorkbenchError("Upload hash mismatch")
        self.store.audit("ftp_upload_intent", path=path, sha256=sha256)
        try:
            with self.ftp() as client:
                deadline = time.monotonic() + 60

                def progress(chunk):
                    if time.monotonic() > deadline:
                        raise WorkbenchError("FTP upload exceeded 60 second deadline")

                client.storbinary("STOR " + path, io.BytesIO(content), callback=progress)
                verified = hashlib.sha256(self._ftp_read(client, path)).hexdigest() == sha256
            self.store.audit("ftp_upload_result", path=path, verified=verified)
            if not verified:
                raise WorkbenchError("FTP readback mismatch; remote file may have changed")
            return {"path": path, "sha256": sha256, "readback_verified": True}
        except Exception as error:
            self.store.audit("ftp_upload_failure", path=path, error=str(error), remote_state="uncertain")
            raise

    def capture_logs(self, seconds=5):
        require_integer(seconds, "seconds", 1, self.profile.limit("log_seconds"))
        started = utc_now()
        deadline = time.monotonic() + seconds
        output = bytearray()
        reason = "duration"
        with socket.create_connection((self.profile.host, self.profile.data["ports"]["klog"]), self.profile.timeout) as connection:
            while time.monotonic() < deadline:
                connection.settimeout(min(self.profile.timeout, max(0.001, deadline - time.monotonic())))
                try:
                    chunk = connection.recv(min(65536, self.profile.limit("log_bytes") - len(output)))
                except socket.timeout:
                    continue
                if not chunk:
                    reason = "eof"
                    break
                output.extend(chunk)
                if len(output) == self.profile.limit("log_bytes"):
                    reason = "byte_limit"
                    break
        return self.store.save("klog", bytes(output), {"started_at": started, "ended_at": utc_now(),
                               "stop_reason": reason, "reconnected": False})

    def inspect_payload(self, manifest):
        record = json.loads(self.store.read(manifest, 65536))
        content = self.store.read(record["artifact"])
        digest = hashlib.sha256(content).hexdigest()
        if digest != require_hash(record["sha256"]):
            raise WorkbenchError("Payload hash does not match manifest")
        if record.get("firmware") != "14.00" or record.get("afterglow_commit") != self.profile.data["jailbreak"].get("installed_commit"):
            raise WorkbenchError("Payload manifest does not match firmware / installed Afterglow commit")
        if record.get("hen_build") != self.profile.data["jailbreak"].get("hen_build") or not record.get("hen_build"):
            raise WorkbenchError("Payload manifest must match actual HEN build")
        if record.get("format") != "bin" or record.get("loader") != "goldhen-binloader":
            raise WorkbenchError("Only explicitly qualified BIN / GoldHEN BinLoader artifacts may execute")
        if not content or content.startswith(b"\x7fELF"):
            raise WorkbenchError("Empty or ELF artifact is not a qualified BIN payload")
        if not re.fullmatch(r"[0-9a-f]{40}", record.get("source_commit") or ""):
            raise WorkbenchError("Record the payload source commit")
        return {"manifest": record, "actual_sha256": digest, "size": len(content), "execution_verified": False}

    def send_payload(self, manifest, sha256):
        qualification = self.profile.require("payload_execute")
        inspected = self.inspect_payload(manifest)
        if inspected["actual_sha256"] != require_hash(sha256) or sha256 not in qualification.get("payload_sha256_allowlist", []):
            raise WorkbenchError("Payload is not in the local hardware-qualified hash allowlist")
        content = self.store.read(inspected["manifest"]["artifact"])
        if hashlib.sha256(content).hexdigest() != sha256:
            raise WorkbenchError("Payload changed after inspection")
        self.store.audit("payload_send_intent", sha256=sha256, size=len(content))
        try:
            with socket.create_connection((self.profile.host, self.profile.data["ports"]["payload"]), self.profile.timeout) as connection:
                connection.sendall(content)
                connection.shutdown(socket.SHUT_WR)
        except OSError as error:
            self.store.audit("payload_send_uncertain", sha256=sha256, error=str(error))
            raise WorkbenchError("Payload transfer uncertain; NEVER retry automatically. Inspect console first") from error
        self.store.audit("payload_bytes_sent", sha256=sha256, execution_verified=False)
        return {"bytes_sent": len(content), "sha256": sha256, "execution_verified": False,
                "warning": "BinLoader has no execution acknowledgement; no automatic retry"}
