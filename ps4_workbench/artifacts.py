import hashlib
import io
import json
import os
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .config import WorkbenchError


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class ArtifactStore:
    def __init__(self, profile):
        self.profile = profile
        self.root = profile.artifact_root
        self.audit_lock = threading.Lock()

    def path(self, relative, must_exist=True):
        if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
                or ":" in relative or "\0" in relative or ".." in relative.replace("\\", "/").split("/")):
            raise WorkbenchError("Use a relative path inside the artifact directory")
        candidate = (self.root / relative).resolve()
        if not candidate.is_relative_to(self.root) or candidate == self.root:
            raise WorkbenchError("Artifact path escapes the artifact directory")
        if must_exist and not candidate.is_file():
            raise WorkbenchError(f"Artifact does not exist: {relative}")
        return candidate

    def save(self, kind, content, metadata=None, extension="bin"):
        identifier = f"{kind}-{uuid.uuid4().hex}"
        relative = f"{identifier}.{extension}"
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.path(relative, must_exist=False)
        with target.open("xb") as stream:
            stream.write(content)
        record = {"id": identifier, "path": relative, "size": len(content),
                  "sha256": hashlib.sha256(content).hexdigest(), "created_at": utc_now(),
                  "profile_sha256": self.profile.fingerprint,
                  "firmware": self.profile.data["firmware"],
                  "jailbreak": self.profile.data["jailbreak"],
                  "debugger": self.profile.data["debugger"], "metadata": metadata or {}}
        self.path(relative + ".json", must_exist=False).write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    def read(self, relative, maximum=None):
        maximum = maximum or self.profile.limit("transfer_bytes")
        with self.path(relative).open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise WorkbenchError("Artifact exceeds the configured size limit")
        return data

    def audit(self, action, **fields):
        self.root.mkdir(parents=True, exist_ok=True)
        entry = {"time": utc_now(), "action": action, "profile_sha256": self.profile.fingerprint, **fields}
        with self.audit_lock, self.path("audit.jsonl", must_exist=False).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def inventory(self):
        if not self.root.exists():
            return []
        result = []
        total = 0
        for path in sorted(self.root.glob("*-*.*.json"))[:self.profile.limit("list_entries")]:
            self.path(path.name)
            content = self.read(path.name)
            total += len(content)
            if total > self.profile.limit("transfer_bytes"):
                raise WorkbenchError("Artifact metadata inventory exceeds limit; archive older captures locally")
            result.append(json.loads(content))
        return result

    def bundle(self, paths, notes):
        if not 1 <= len(paths) <= 100:
            raise WorkbenchError("Select 1 to 100 artifacts")
        selected = {}
        total = 0
        for relative in paths:
            for name in (relative, relative + ".json"):
                if name != relative and not self.path(name, must_exist=False).is_file():
                    continue
                selected[name] = self.read(name)
                total += len(selected[name])
                if total > self.profile.limit("transfer_bytes"):
                    raise WorkbenchError("Experiment bundle exceeds transfer limit")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("experiment.json", json.dumps({"notes": notes, "time": utc_now(),
                              "profile": self.profile.data, "profile_sha256": self.profile.fingerprint}, indent=2))
            for relative, content in selected.items():
                archive.writestr("artifacts/" + self.path(relative).relative_to(self.root).as_posix(), content)
        return self.save("experiment", output.getvalue(), {"paths": paths}, "zip")
