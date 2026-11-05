import hashlib
import io
import json
import struct
import zipfile
from unittest.mock import Mock, patch

from ps4_workbench.analysis import scan_pattern, typed_value
from ps4_workbench.config import Profile, WorkbenchError
from ps4_workbench.tools import ToolRegistry
from ps4_workbench.transports import remote_path

from .support import FakeSocket, WorkbenchCase


class SafetyTests(WorkbenchCase):
    def test_default_status_makes_no_network_connections(self):
        with patch("socket.create_connection") as connect:
            result = self.workbench.console.status()
            connect.assert_not_called()
        self.assertEqual(result["compatibility"]["state"], "hardware_unverified")

    def test_probe_never_touches_payload_port(self):
        with patch("socket.create_connection", side_effect=lambda *args: FakeSocket()) as connect:
            self.workbench.console.status(probe=True)
        self.assertEqual({call.args[0][1] for call in connect.call_args_list}, {744, 2121, 3232})

    def test_wrong_firmware_profile_fails(self):
        self.settings["firmware"] = "12.02"
        with self.assertRaisesRegex(WorkbenchError, "14.00"):
            self.reload()

    def test_public_or_unspecified_host_fails(self):
        for host in ("8.8.8.8", "0.0.0.0", "224.0.0.1", "::1", "localhost"):
            self.settings["host"] = host
            with self.assertRaises((WorkbenchError, ValueError)):
                self.reload()

    def test_permission_boolean_not_string(self):
        self.settings["permissions"]["payload_execute"] = "false"
        with self.assertRaisesRegex(WorkbenchError, "boolean"):
            self.reload()

    def test_payload_port_cannot_alias_probe_port(self):
        self.settings["ports"]["debug"] = 9090
        with self.assertRaisesRegex(WorkbenchError, "distinct"):
            self.reload()

    def test_unknown_probe_services_cannot_alias_payload(self):
        self.settings["ports"]["other"] = 9090
        with self.assertRaisesRegex(WorkbenchError, "service ports"):
            self.reload()

    def test_missing_timeout_has_working_default(self):
        del self.settings["timeout_seconds"]
        self.reload()
        self.assertEqual(self.profile.timeout, 3)

    def test_malformed_qualification_is_unverified_not_crash(self):
        self.profile.qualification_path.write_text("not JSON")
        self.assertEqual(self.workbench.console.status()["compatibility"]["state"], "hardware_unverified")

    def test_qualification_array_is_rejected(self):
        self.profile.qualification_path.write_text("[]")
        with self.assertRaisesRegex(WorkbenchError, "JSON object"):
            self.profile.qualification()

    def test_profile_requires_host_string(self):
        self.settings["host"] = 2130706433
        with self.assertRaisesRegex(WorkbenchError, "string"):
            self.reload()

    def test_stale_qualification_fails_closed(self):
        self.qualify("process_write")
        self.assertIn("process_write", self.profile.require("process_write")["approved_permissions"])
        self.settings["jailbreak"]["hen_build"] = "changed-hen"
        self.reload()
        with self.assertRaisesRegex(WorkbenchError, "stale"):
            self.profile.require("process_write")

    def test_enabled_flag_without_attestation_is_not_enough(self):
        self.settings["permissions"]["process_write"] = True
        self.reload()
        with self.assertRaisesRegex(WorkbenchError, "qualification"):
            self.profile.require("process_write")

    def test_qualification_must_approve_specific_permission(self):
        self.qualify("ftp_upload")
        self.profile.data["permissions"]["process_write"] = True
        record = json.loads(self.profile.qualification_path.read_text())
        record["profile_sha256"] = self.profile.fingerprint
        self.profile.qualification_path.write_text(json.dumps(record))
        with self.assertRaisesRegex(WorkbenchError, "does not approve"):
            self.profile.require("process_write")

    def test_artifact_paths_reject_escapes_and_windows_streams(self):
        for path in ("../secret", "a/../../secret", "C:\\secret", "/etc/passwd", "file:stream", "a/../file"):
            with self.assertRaises(WorkbenchError):
                self.workbench.store.path(path, must_exist=False)

    def test_artifact_hash_and_provenance(self):
        result = self.workbench.store.save("memory", b"hello", {"pid": 71})
        self.assertEqual(result["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(result["profile_sha256"], self.profile.fingerprint)
        self.assertEqual(self.workbench.store.read(result["path"]), b"hello")

    def test_inventory_includes_annotations_and_bundles(self):
        memory = self.workbench.store.save("memory", b"hello")
        self.workbench.analysis.annotate(memory["path"], "a" * 64, 0x1234, "evidence")
        self.workbench.store.bundle([memory["path"]], "test")
        self.assertEqual(len(self.workbench.store.inventory()), 3)

    def test_bundle_contains_selected_files_and_sidecars(self):
        memory = self.workbench.store.save("memory", b"hello")
        result = self.workbench.store.bundle([memory["path"]], "test notes")
        with zipfile.ZipFile(io.BytesIO(self.workbench.store.read(result["path"]))) as archive:
            self.assertIn("artifacts/" + memory["path"], archive.namelist())
            self.assertIn("artifacts/" + memory["path"] + ".json", archive.namelist())
            self.assertEqual(json.loads(archive.read("experiment.json"))["notes"], "test notes")

    def test_remote_paths_reject_injection_and_traversal(self):
        for path in ("relative", "/data/../secret", "/data/x\r\nDELE /x", "/data\\x", "/data/x\0"):
            with self.assertRaises(WorkbenchError):
                remote_path(path)
        self.assertEqual(remote_path("/data//folder/./file"), "/data/folder/file")

    def test_ftp_download_enforces_cap_without_size_support(self):
        self.settings["limits"]["transfer_bytes"] = 4
        self.reload()
        client = Mock()
        client.retrbinary.side_effect = lambda command, callback: callback(b"12345")
        with self.assertRaisesRegex(WorkbenchError, "limit"):
            self.workbench.console._ftp_read(client, "/data/file")

    def test_ftp_upload_path_allowlist_before_connection(self):
        self.qualify("ftp_upload")
        with patch.object(self.workbench.console, "ftp") as ftp:
            with self.assertRaisesRegex(WorkbenchError, "upload roots"):
                self.workbench.console.ftp_upload("none", "/system/file", "a" * 64)
            ftp.assert_not_called()

    def payload_manifest(self, content=b"test-payload", format="bin", loader="goldhen-binloader"):
        binary = self.workbench.store.save("payload", content)
        record = {"artifact": binary["path"], "sha256": binary["sha256"], "firmware": "14.00",
                  "afterglow_commit": self.profile.data["jailbreak"]["installed_commit"],
                  "hen_build": self.profile.data["jailbreak"]["hen_build"], "format": format,
                  "loader": loader, "source_commit": "c" * 40}
        manifest = self.workbench.store.save("manifest", json.dumps(record).encode())
        return manifest["path"], binary["sha256"]

    def test_payload_requires_permission_before_network(self):
        with patch("socket.create_connection") as connect:
            with self.assertRaisesRegex(WorkbenchError, "Disabled"):
                self.workbench.console.send_payload("not-present", "a" * 64)
            connect.assert_not_called()

    def test_elf_payload_is_never_sent_to_binloader(self):
        self.qualify("payload_execute")
        manifest, digest = self.payload_manifest(content=b"\x7fELFtest")
        with patch("socket.create_connection") as connect:
            with self.assertRaisesRegex(WorkbenchError, "ELF"):
                self.workbench.console.send_payload(manifest, digest)
            connect.assert_not_called()

    def test_payload_requires_artifact_allowlist(self):
        self.qualify("payload_execute")
        manifest, digest = self.payload_manifest()
        with self.assertRaisesRegex(WorkbenchError, "allowlist"):
            self.workbench.console.send_payload(manifest, digest)

    def test_payload_transport_failure_is_uncertain_and_never_retried(self):
        digest = hashlib.sha256(b"test-payload").hexdigest()
        self.qualify("payload_execute", payloads=[digest])
        manifest, _ = self.payload_manifest()
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        stream.sendall.side_effect = OSError("connection reset after partial transfer")
        with patch("socket.create_connection", return_value=stream) as connect:
            with self.assertRaisesRegex(WorkbenchError, "NEVER retry"):
                self.workbench.console.send_payload(manifest, digest)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(stream.sendall.call_count, 1)
        self.assertIn("payload_send_uncertain", self.workbench.store.path("audit.jsonl").read_text())

    def test_payload_bytes_sent_is_not_execution_success(self):
        digest = hashlib.sha256(b"test-payload").hexdigest()
        self.qualify("payload_execute", payloads=[digest])
        manifest, _ = self.payload_manifest()
        stream = FakeSocket()
        with patch("socket.create_connection", return_value=stream):
            result = self.workbench.console.send_payload(manifest, digest)
        self.assertFalse(result["execution_verified"])
        self.assertEqual(stream.sent, b"test-payload")

    def test_compare_before_write_mismatch_prevents_write(self):
        self.qualify("process_write")
        self.workbench.debugger.read_memory = Mock(return_value=b"old")
        self.workbench.debugger.write_memory = Mock()
        with self.assertRaisesRegex(WorkbenchError, "Original bytes differ"):
            self.workbench.memory_write(71, 0x4000, b"new".hex(), b"bad".hex())
        self.workbench.debugger.write_memory.assert_not_called()

    def test_write_keeps_backup_replacement_and_readback(self):
        self.qualify("process_write")
        self.workbench.debugger.read_memory = Mock(side_effect=[b"old", b"new"])
        self.workbench.debugger.write_memory = Mock()
        result = self.workbench.memory_write(71, 0x4000, b"new".hex(), b"old".hex())
        self.assertTrue(result["verified"])
        self.assertEqual(self.workbench.store.read(result["backup"]["path"]), b"old")
        self.assertEqual(self.workbench.store.read(result["replacement"]["path"]), b"new")
        self.assertEqual(self.workbench.store.read(result["readback"]["path"]), b"new")

    def test_readback_mismatch_logs_uncertainty_without_retry(self):
        self.qualify("process_write")
        self.workbench.debugger.read_memory = Mock(side_effect=[b"old", b"bad"])
        self.workbench.debugger.write_memory = Mock()
        with self.assertRaisesRegex(WorkbenchError, "readback mismatch"):
            self.workbench.memory_write(71, 0x4000, b"new".hex(), b"old".hex())
        self.workbench.debugger.write_memory.assert_called_once()
        self.assertIn("memory_write_uncertain", self.workbench.store.path("audit.jsonl").read_text())

    def test_pattern_wildcards_and_result_limit(self):
        result = scan_pattern(b"\x01\x02\x01\x03\x01\x04", "01 ??", max_results=2)
        self.assertEqual(result["matches"], ["0x0", "0x2"])
        self.assertTrue(result["truncated"])

    def test_pattern_invalid_tokens(self):
        for pattern in ("", "-1", "+f", "100", "GG", "?"):
            with self.assertRaises(WorkbenchError):
                scan_pattern(b"test", pattern)

    def test_typed_uint64_does_not_lose_json_precision(self):
        self.assertEqual(typed_value(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF), "u64")["value"], "18446744073709551615")

    def test_typed_nan_is_json_safe(self):
        result = typed_value(struct.pack("<f", float("nan")), "f32")
        json.dumps(result, allow_nan=False)
        self.assertEqual(result["value"], "nan")

    def test_diff(self):
        left = self.workbench.store.save("memory", b"abcde")
        right = self.workbench.store.save("memory", b"aXYde!")
        result = self.workbench.analysis.diff(left["path"], right["path"])
        self.assertEqual(result["changed_bytes"], 3)
        self.assertEqual(result["ranges"], [{"offset": 1, "length": 2}, {"offset": 5, "length": 1}])


class ToolTests(WorkbenchCase):
    def test_mutations_hidden_by_default(self):
        registry = ToolRegistry(self.workbench)
        names = {tool.name for tool in registry.available()}
        for name in ("payload_execute", "memory_write", "kernel_read", "kernel_write", "debug_attach", "sdk_build", "ftp_upload"):
            self.assertNotIn(name, names)
            with self.assertRaisesRegex(WorkbenchError, "disabled"):
                registry.call(name, {})

    def test_schema_rejects_unknown_arguments_before_network(self):
        with patch("socket.create_connection") as connect:
            with self.assertRaisesRegex(WorkbenchError, "Unknown"):
                ToolRegistry(self.workbench).call("console_status", {"execute_payload": True})
            connect.assert_not_called()

    def test_schema_rejects_bool_instead_of_pid(self):
        with self.assertRaisesRegex(WorkbenchError, "integer"):
            ToolRegistry(self.workbench).call("process_info", {"pid": True})

    def test_schema_rejects_oversized_addresses(self):
        with self.assertRaises(WorkbenchError):
            ToolRegistry(self.workbench).call("memory_read", {"pid": 1, "address": "18446744073709551616", "length": 1})

    def test_large_results_saved_not_inline(self):
        registry = ToolRegistry(self.workbench)
        registry.add("large", "test", lambda: {"data": "x" * 25000})
        result = registry.call("large", {})
        self.assertIn("result_saved", result)
        self.assertEqual(len(json.loads(self.workbench.store.read(result["result_saved"]["path"]))["data"]), 25000)

    def test_large_wire_integers_are_exact_strings(self):
        registry = ToolRegistry(self.workbench)
        registry.add("large_integer", "test", lambda: {"address": 0xFFFFFFFF80001000})
        self.assertEqual(registry.call("large_integer", {})["address"], "0xffffffff80001000")

    def test_no_policy_or_qualification_tool(self):
        registry = ToolRegistry(self.workbench)
        self.assertFalse(any("qualify" in name or "permission" in name for name in registry.tools))
