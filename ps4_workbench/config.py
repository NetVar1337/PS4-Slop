import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path


class WorkbenchError(Exception):
    pass


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise WorkbenchError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def require_hash(value, name="sha256"):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise WorkbenchError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class Profile:
    path: Path
    data: dict

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise WorkbenchError("Profile must be a JSON object")
        for section in ("jailbreak", "debugger", "ports", "limits", "permissions"):
            if not isinstance(data.get(section), dict):
                raise WorkbenchError(f"Profile needs an object section: {section}")
        for setting in ("artifact_directory", "qualification_file"):
            if not isinstance(data.get(setting), str) or not data[setting].strip():
                raise WorkbenchError(f"Profile needs a nonempty {setting}")
        if data.get("firmware") != "14.00":
            raise WorkbenchError("This release supports only the 14.00 profile; no offset fallback")
        if not isinstance(data.get("host"), str):
            raise WorkbenchError("Console host must be a private IPv4 string")
        address = ipaddress.ip_address(data["host"])
        if address.version != 4 or not (address.is_private or address.is_loopback) or address.is_unspecified or address.is_multicast:
            raise WorkbenchError("Console host must be a private or loopback IPv4 literal")
        if data["jailbreak"].get("repository") != "https://github.com/well0nez/afterglow-web":
            raise WorkbenchError("Only the configured Afterglow host is supported")
        if data["debugger"].get("backend") != "ps4debug-ng" or data["debugger"].get("protocol") != "1.3":
            raise WorkbenchError("Unsupported debugger backend or protocol")
        if set(data["ports"]) != {"payload", "ftp", "klog", "debug"}:
            raise WorkbenchError("Only payload, ftp, klog and debug service ports are allowed")
        for service in ("payload", "ftp", "klog", "debug"):
            require_integer(data["ports"][service], f"ports.{service}", 1, 65535)
        if len(set(data["ports"][name] for name in ("payload", "ftp", "klog", "debug"))) != 4:
            raise WorkbenchError("Service ports must be distinct; never use a payload port for read-only probes")
        timeout = data.get("timeout_seconds", 3)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
            raise WorkbenchError("timeout_seconds must be between 0.1 and 30")
        data["timeout_seconds"] = timeout
        caps = {"memory_bytes": 1048576, "transfer_bytes": 67108864, "log_bytes": 16777216,
                "log_seconds": 120, "list_entries": 16384}
        for name, maximum in caps.items():
            require_integer(data["limits"][name], name, 1, maximum)
        for name in ("ftp_upload", "payload_execute", "process_write", "debug_control", "kernel_read", "kernel_write", "build"):
            if type(data["permissions"].get(name)) is not bool:
                raise WorkbenchError(f"permissions.{name} must be boolean")
        for name in ("reference_commit", "installed_commit"):
            commit = data["jailbreak"].get(name)
            if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise WorkbenchError(f"Invalid jailbreak {name}")
        if data["debugger"].get("payload_sha256") is not None:
            require_hash(data["debugger"]["payload_sha256"])
        brand = data["debugger"].get("expected_brand")
        if brand is not None and (not isinstance(brand, str) or not brand.startswith("ps4debug-NG by Pharaoh2k v") or len(brand) > 256):
            raise WorkbenchError("Invalid expected debugger branding")
        if not isinstance(data.get("ftp_upload_roots"), list) or not all(isinstance(root, str) for root in data["ftp_upload_roots"]):
            raise WorkbenchError("ftp_upload_roots must be a list of POSIX paths")
        return cls(path, data)

    @property
    def host(self):
        return self.data["host"]

    @property
    def timeout(self):
        return self.data["timeout_seconds"]

    @property
    def fingerprint(self):
        return canonical_hash(self.data)

    @property
    def artifact_root(self):
        return (self.path.parent / self.data["artifact_directory"]).resolve()

    @property
    def qualification_path(self):
        return (self.path.parent / self.data["qualification_file"]).resolve()

    def limit(self, name):
        return self.data["limits"][name]

    def require(self, permission):
        if not self.data["permissions"].get(permission, False):
            raise WorkbenchError(f"Disabled by local profile: {permission}")
        qualification = self.qualification()
        if permission not in qualification.get("approved_permissions", []):
            raise WorkbenchError(f"Hardware qualification does not approve {permission}")
        return qualification

    def qualification(self):
        try:
            record = json.loads(self.qualification_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise WorkbenchError("No readable local hardware qualification; see CLI qualify and docs/COMPATIBILITY.md") from error
        if not isinstance(record, dict):
            raise WorkbenchError("Qualification must be a JSON object")
        if record.get("profile_sha256") != self.fingerprint or record.get("attestation") != "I_TESTED_THIS_EXACT_CONFIGURATION":
            raise WorkbenchError("Qualification is stale or invalid; profile must match exactly")
        if not self.data["jailbreak"].get("installed_commit") or not self.data["jailbreak"].get("hen_build"):
            raise WorkbenchError("Record the actual installed Afterglow commit and HEN build first")
        if not isinstance(record.get("approved_permissions"), list):
            raise WorkbenchError("Invalid qualification permissions")
        return record
