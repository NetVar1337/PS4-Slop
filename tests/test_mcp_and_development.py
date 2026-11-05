import argparse
import hashlib
import io
import json
import sys
from unittest.mock import patch

from ps4_workbench.cli import main, write_qualification
from ps4_workbench.config import WorkbenchError
from ps4_workbench.development import Development
from ps4_workbench.mcp import MAX_MESSAGE, MCPServer
from ps4_workbench.tools import ToolRegistry

from .support import WorkbenchCase


def request(method, params=None, identifier=1):
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}


class MCPTests(WorkbenchCase):
    def setUp(self):
        super().setUp()
        self.server = MCPServer(ToolRegistry(self.workbench))

    def initialize(self):
        result = self.server.dispatch(request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "tests", "version": "1"}}))
        self.server.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def test_initialization_lifecycle(self):
        self.assertIn("error", self.server.dispatch(request("tools/list")))
        result = self.initialize()
        self.assertEqual(result["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("tools", self.server.dispatch(request("tools/list"))["result"])

    def test_unsupported_version_negotiates_supported_version(self):
        result = self.server.dispatch(request("initialize", {"protocolVersion": "unknown", "capabilities": {}, "clientInfo": {}}))
        self.assertEqual(result["result"]["protocolVersion"], "2025-11-25")

    def test_invalid_initialize_does_not_initialize(self):
        self.assertIn("error", self.server.dispatch(request("initialize")))
        self.assertFalse(self.server.initialized)

    def test_tool_failure_is_mcp_error_content(self):
        self.initialize()
        result = self.server.dispatch(request("tools/call", {"name": "memory_write", "arguments": {}}))
        self.assertTrue(result["result"]["isError"])
        self.assertNotIn("error", result)

    def test_status_tool_no_network(self):
        self.initialize()
        with patch("socket.create_connection") as connect:
            result = self.server.dispatch(request("tools/call", {"name": "console_status"}))
            connect.assert_not_called()
        content = json.loads(result["result"]["content"][0]["text"])
        self.assertEqual(content["compatibility"]["state"], "hardware_unverified")

    def test_notifications_have_no_response(self):
        self.assertIsNone(self.server.dispatch({"jsonrpc": "2.0", "method": "notifications/cancelled"}))

    def test_invalid_request_ids_and_batches(self):
        for invalid in ([], request("ping", identifier=True), request("ping", identifier=None)):
            self.assertEqual(self.server.dispatch(invalid)["error"]["code"], -32600)

    def test_unknown_method(self):
        self.initialize()
        self.assertEqual(self.server.dispatch(request("unknown"))["error"]["code"], -32601)

    def test_stream_parse_errors_and_ping_no_stdout_noise(self):
        incoming = io.BytesIO(b"{invalid}\n" + json.dumps(request("ping")).encode() + b"\n")
        outgoing = io.BytesIO()
        self.server.serve(incoming, outgoing)
        messages = [json.loads(line) for line in outgoing.getvalue().splitlines()]
        self.assertEqual(messages[0]["error"]["code"], -32700)
        self.assertEqual(messages[1]["result"], {})

    def test_nonfinite_json_rejected(self):
        incoming = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":NaN}}\n')
        outgoing = io.BytesIO()
        self.server.serve(incoming, outgoing)
        self.assertEqual(json.loads(outgoing.getvalue())["error"]["code"], -32700)

    def test_oversize_input_closes_transport(self):
        incoming = io.BytesIO(b"x" * (MAX_MESSAGE + 1))
        outgoing = io.BytesIO()
        self.server.serve(incoming, outgoing)
        self.assertIn("exceeds", json.loads(outgoing.getvalue())["error"]["message"])

    def test_eof_always_cleans_up_session(self):
        with patch.object(self.workbench, "close") as close:
            self.server.serve(io.BytesIO(), io.BytesIO())
            close.assert_called_once()


class DevelopmentTests(WorkbenchCase):
    def test_scaffold_is_explicitly_not_a_ready_binary(self):
        result = Development(self.profile, self.workbench.store).scaffold("plugin", "my-plugin")
        self.assertFalse(result["ready_to_build"])
        self.assertTrue(self.workbench.store.path(result["recipe"]).is_file())

    def test_scaffold_no_overwrite_or_traversal(self):
        development = Development(self.profile, self.workbench.store)
        development.scaffold("homebrew", "sample")
        with self.assertRaises(FileExistsError):
            development.scaffold("homebrew", "sample")
        with self.assertRaises(WorkbenchError):
            development.scaffold("homebrew", "../bad")

    def recipe(self, code="from pathlib import Path; Path('output.bin').write_bytes(b'test')", output="output.bin"):
        development = Development(self.profile, self.workbench.store)
        scaffold = development.scaffold("homebrew", "sample")
        recipe = {"sdk": "homebrew", "source_commit": "a" * 40,
                  "commands": [[sys.executable, "-c", code]], "environment": {}, "output": output, "timeout_seconds": 5}
        content = json.dumps(recipe).encode()
        path = self.workbench.store.path(scaffold["recipe"])
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        self.qualify("build", recipes=[digest])
        return scaffold["recipe"], digest

    def test_build_recipe_runs_locally_and_never_deploys(self):
        recipe, digest = self.recipe()
        with patch("socket.create_connection") as connect:
            result = Development(self.profile, self.workbench.store).build(recipe, digest)
            connect.assert_not_called()
        self.assertFalse(result["deployed"])
        self.assertFalse(result["hardware_verified"])
        self.assertEqual(self.workbench.store.read(result["artifact"]["path"]), b"test")

    def test_build_recipe_hash_change_blocks_execution(self):
        recipe, digest = self.recipe()
        self.workbench.store.path(recipe).write_text("{}")
        with patch("subprocess.Popen") as process:
            with self.assertRaisesRegex(WorkbenchError, "SHA-256"):
                Development(self.profile, self.workbench.store).build(recipe, digest)
            process.assert_not_called()

    def test_build_failure_archives_log(self):
        recipe, digest = self.recipe("print('build failed'); raise SystemExit(2)")
        with self.assertRaisesRegex(WorkbenchError, "Build failed"):
            Development(self.profile, self.workbench.store).build(recipe, digest)
        self.assertIn("build_failure", self.workbench.store.path("audit.jsonl").read_text())

    def test_build_output_must_stay_in_project(self):
        recipe, digest = self.recipe(output="../escape.bin")
        with self.assertRaisesRegex(WorkbenchError, "inside project"):
            Development(self.profile, self.workbench.store).build(recipe, digest)

    def test_build_output_cannot_be_stale(self):
        recipe, digest = self.recipe()
        output = self.workbench.store.path(recipe).parent / "output.bin"
        output.write_bytes(b"stale")
        with self.assertRaisesRegex(WorkbenchError, "already exists"):
            Development(self.profile, self.workbench.store).build(recipe, digest)

    def test_build_log_limit_terminates_foreground_command(self):
        self.settings["limits"]["log_bytes"] = 128
        self.reload()
        recipe, digest = self.recipe("print('x' * 8192)")
        with self.assertRaisesRegex(WorkbenchError, "Build failed"):
            Development(self.profile, self.workbench.store).build(recipe, digest)
        entries = self.workbench.store.inventory()
        logs = [entry for entry in entries if entry["id"].startswith("build-log-")]
        self.assertEqual(logs[0]["size"], 128)

    def test_build_deadline_terminates_foreground_command(self):
        recipe, _ = self.recipe("import time; time.sleep(10)")
        path = self.workbench.store.path(recipe)
        data = json.loads(path.read_bytes())
        data["timeout_seconds"] = 1
        content = json.dumps(data).encode()
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        self.qualify("build", recipes=[digest])
        with self.assertRaisesRegex(WorkbenchError, "Build failed"):
            Development(self.profile, self.workbench.store).build(recipe, digest)



class CLITests(WorkbenchCase):
    def test_validate_command_no_network(self):
        with patch("socket.create_connection") as connect, patch("sys.stdout", new_callable=io.StringIO) as output:
            result = main(["--profile", str(self.profile_path), "validate"])
            connect.assert_not_called()
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["compatibility"]["state"], "hardware_unverified")

    def test_local_ingest(self):
        source = self.directory / "source.bin"
        source.write_bytes(b"local")
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["--profile", str(self.profile_path), "ingest", str(source)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(self.workbench.store.read(result["path"]), b"local")

    def test_qualification_does_not_invent_installed_versions(self):
        arguments = argparse.Namespace(attest="I_TESTED_THIS_EXACT_CONFIGURATION")
        with self.assertRaisesRegex(WorkbenchError, "actual"):
            write_qualification(self.profile, arguments)

    def test_qualification_records_evidence_not_guarantee(self):
        self.settings["jailbreak"].update(installed_commit="a" * 40, hen_build="test-hen")
        self.settings["permissions"]["ftp_upload"] = True
        self.reload()
        evidence = self.directory / "evidence.txt"
        evidence.write_text("I tested this configuration on my hardware")
        arguments = argparse.Namespace(attest="I_TESTED_THIS_EXACT_CONFIGURATION", evidence=str(evidence),
                                       approve=["ftp_upload"], payload_sha256=[], build_recipe_sha256=[], replace=False)
        result = write_qualification(self.profile, arguments)
        self.assertFalse(result["record"]["hardware_compatibility_guaranteed"])
        self.assertIn("ftp_upload", self.profile.require("ftp_upload")["approved_permissions"])
