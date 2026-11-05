import json
import tempfile
import unittest
from pathlib import Path

from ps4_workbench.config import Profile
from ps4_workbench.workbench import Workbench


ROOT = Path(__file__).resolve().parents[1]


class WorkbenchCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.settings = json.loads((ROOT / "profiles/ps4-1400.json").read_text(encoding="utf-8"))
        self.settings.update(host="127.0.0.1", artifact_directory="artifacts", qualification_file="qualification.json")
        self.profile_path = self.directory / "profile.json"
        self.reload()

    def reload(self):
        self.profile_path.write_text(json.dumps(self.settings), encoding="utf-8")
        self.profile = Profile.load(self.profile_path)
        self.workbench = Workbench(self.profile)

    def qualify(self, *permissions, payloads=None, recipes=None):
        for permission in permissions:
            self.settings["permissions"][permission] = True
        self.settings["jailbreak"].update(installed_commit="a" * 40, hen_build="test-hen")
        self.settings["debugger"].update(expected_brand="ps4debug-NG by Pharaoh2k v1.3.4", payload_sha256="b" * 64)
        self.reload()
        self.profile.qualification_path.write_text(json.dumps({
            "profile_sha256": self.profile.fingerprint, "attestation": "I_TESTED_THIS_EXACT_CONFIGURATION",
            "approved_permissions": list(permissions), "debugger_payload_sha256": "b" * 64,
            "payload_sha256_allowlist": payloads or [], "build_recipe_sha256_allowlist": recipes or []
        }), encoding="utf-8")


class FakeSocket:
    def __init__(self, response=b"", fragment=65536):
        self.response = bytearray(response)
        self.fragment = fragment
        self.sent = bytearray()
        self.closed = False
        self.timeouts = []

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, length):
        count = min(length, self.fragment, len(self.response))
        result = bytes(self.response[:count])
        del self.response[:count]
        return result

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def close(self):
        self.closed = True

    def shutdown(self, direction):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.close()
