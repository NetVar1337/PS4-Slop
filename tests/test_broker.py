import contextlib
import json
import subprocess
import sys
import threading
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ps4_workbench.broker import BrokerServer, SessionHub, load_token
from ps4_workbench.client import BrokerClient, RemoteRegistry
from ps4_workbench.config import WorkbenchError
from ps4_workbench.mcp import MCPServer
from ps4_workbench.tools import ToolRegistry

from .support import ROOT, WorkbenchCase


class BrokerCase(WorkbenchCase):
    def setUp(self):
        super().setUp()
        self.qualify("debug_control", "process_write")
        debugger = self.workbench.debugger

        def attach(pid, listen_address):
            debugger.attached_pid = pid
            return {"pid": pid, "attached": True}

        def detach():
            debugger.attached_pid = None
            return {"detached": True}

        debugger.attach = Mock(side_effect=attach)
        debugger.detach = Mock(side_effect=detach)
        debugger.poll_events = Mock(return_value=[])
        debugger.control = Mock(return_value={"acknowledged": True})
        debugger.threads = Mock(return_value=[72])
        debugger.get_registers = Mock(return_value={"rip": "0x4000", "rax": "0x1234", "rsp": "0x8000", "rflags": "0x202"})
        debugger.read_memory = Mock(side_effect=lambda pid, address, length: b"A" * length)
        debugger.maps = Mock(return_value=[{"start": 0x4000, "end": 0x8000, "protection": 5, "offset": 0, "name": "sample"}])
        debugger.breakpoint = Mock(return_value={"enabled": True})
        debugger.watchpoint = Mock(return_value={"enabled": True})
        self.hub = SessionHub(ToolRegistry(self.workbench))
        self.secret_path = self.directory / "broker-token.local"
        self.secret = load_token(self.secret_path, create=True)
        self.addCleanup(self.hub.close)

    @contextlib.contextmanager
    def broker(self):
        with BrokerServer(self.hub, self.secret, port=0) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                yield "http://127.0.0.1:" + str(server.server_port)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def stop_event(self):
        self.workbench.debugger.poll_events.return_value = [{"thread_id": 72, "status": 0x57F,
                                                           "registers": {"rip": "0x4000"}, "name": "sample", "raw_hex": "00"}]
        self.hub.pump()
        self.workbench.debugger.poll_events.return_value = []


class BrokerTests(BrokerCase):
    def test_token_not_overwritten_or_printed(self):
        self.assertEqual(load_token(self.secret_path, create=True), self.secret)
        self.assertEqual(len(self.secret), 64)

    def test_client_rejects_remote_urls_and_credentials(self):
        for url in ("http://192.168.1.1:8765", "https://127.0.0.1:8765", "http://user@127.0.0.1:8765", "http://127.0.0.1:8765/other"):
            with self.assertRaises(WorkbenchError):
                BrokerClient(url, self.secret_path)

    def test_broker_startup_and_status_do_not_connect_to_console(self):
        with self.broker() as url, patch.object(self.workbench.debugger, "_connect") as connect:
            client = BrokerClient(url, self.secret_path)
            self.assertIsNone(client.state()["attached_pid"])
            self.assertEqual(client.call("console_status")["host"], "127.0.0.1")
            connect.assert_not_called()

    def test_authentication_is_required(self):
        with self.broker() as url:
            request = Request(url + "/rpc", data=b'{"operation":"state"}', headers={"X-PS4-Client": "test"})
            with self.assertRaises(HTTPError) as raised:
                urlopen(request, timeout=2)
            self.assertEqual(raised.exception.code, 401)
            raised.exception.close()

    def test_browser_origins_are_rejected_even_with_token(self):
        with self.broker() as url:
            request = Request(url + "/rpc", data=b'{"operation":"state"}',
                              headers={"Authorization": "Bearer " + self.secret, "X-PS4-Client": "test", "Origin": "http://evil.invalid"})
            with self.assertRaises(HTTPError) as raised:
                urlopen(request, timeout=2)
            self.assertEqual(raised.exception.code, 403)
            raised.exception.close()

    def test_only_one_controller_but_reads_allowed(self):
        self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        with self.assertRaisesRegex(WorkbenchError, "Another client"):
            self.hub.call("ghidra", "debug_control", {"action": "resume"})
        result = self.hub.call("ghidra", "memory_peek", {"pid": 71, "address": "0x4000", "length": 4})
        self.assertEqual(result["hex"], "41414141")

    def test_observer_cannot_detach_controller(self):
        self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        with self.assertRaisesRegex(WorkbenchError, "Another client"):
            self.hub.call("ghidra", "debug_detach", {})
        self.assertEqual(self.hub.state()["attached_pid"], 71)

    def test_event_cursors_are_independent(self):
        self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        self.stop_event()
        first, second = self.hub.events_since(0), self.hub.events_since(0)
        self.assertEqual(first, second)
        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(first["events"][0]["pid"], 71)
        self.assertEqual(self.hub.events_since(first["cursor"])["events"], [])

    def test_event_retention_gap_is_reported(self):
        for index in range(1030):
            self.hub.publish({"type": "test", "index": index})
        result = self.hub.events_since(0)
        self.assertEqual(result["lost_events"], 6)
        self.assertEqual(len(result["events"]), 1024)

    def test_event_pagination_preserves_unread_entries(self):
        for index in range(10):
            self.hub.publish({"type": "test", "index": index})
        first = self.hub.events_since(0, limit=6)
        second = self.hub.events_since(first["cursor"], limit=6)
        self.assertEqual([event["index"] for event in first["events"] + second["events"]], list(range(10)))
        self.assertEqual(first["latest_cursor"], 10)

    def test_future_event_cursor_is_not_silently_reset(self):
        with self.assertRaisesRegex(WorkbenchError, "ahead"):
            self.hub.events_since(1)

    def test_event_channel_failure_is_reported_once_without_fake_stop(self):
        self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        self.workbench.debugger.poll_events.side_effect = WorkbenchError("EOF")
        self.hub.pump()
        self.hub.pump()
        result = self.hub.events_since(0)
        self.assertEqual([event["type"] for event in result["events"]], ["session_error"])
        self.assertEqual(self.hub.state()["execution_state"], "uncertain")

    def test_attach_failure_retains_lease_until_explicit_release(self):
        self.workbench.debugger.attach.side_effect = WorkbenchError("failed")
        with self.assertRaises(WorkbenchError):
            self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        self.assertEqual(self.hub.state()["controller"], "ida")
        self.hub.dispatch("ida", "release", {})
        self.assertIsNone(self.hub.state()["controller"])

    def test_permission_denial_does_not_claim_a_debug_session(self):
        self.workbench.profile.data["permissions"]["debug_control"] = False
        with self.assertRaisesRegex(WorkbenchError, "disabled"):
            self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        self.assertIsNone(self.hub.state()["controller"])
        self.workbench.debugger.attach.assert_not_called()

    def test_payload_sending_blocked_while_attached(self):
        self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        with self.assertRaisesRegex(WorkbenchError, "Detach"):
            self.hub.call("ida", "payload_execute", {})

    def test_mcp_proxy_reads_shared_session_and_does_not_close_owner(self):
        self.hub.call("ida", "debug_attach", {"pid": 71, "listen_address": "127.0.0.1"})
        self.stop_event()
        with self.broker() as url:
            registry = RemoteRegistry(BrokerClient(url, self.secret_path, "mcp"))
            self.assertIn("analysis_decompile", {tool.describe()["name"] for tool in registry.available()})
            self.assertEqual(registry.call("session_state", {})["controller"], "ida")
            self.assertEqual(len(registry.call("session_events", {})["events"]), 1)
            self.assertEqual(registry.call("session_events", {})["events"], [])
            import io
            MCPServer(registry).serve(io.BytesIO(), io.BytesIO())
        self.assertEqual(self.hub.state()["attached_pid"], 71)

    def test_remote_error_is_not_automatically_retried(self):
        with self.broker() as url:
            client = BrokerClient(url, self.secret_path)
            with self.assertRaises(WorkbenchError):
                client.call("not_a_tool")

    def test_client_cannot_accidentally_use_another_profile(self):
        with self.broker() as url:
            with self.assertRaisesRegex(WorkbenchError, "profile mismatch"):
                BrokerClient(url, self.secret_path, expected_profile="0" * 64)

    def test_existing_client_is_bound_to_original_profile(self):
        with self.broker() as url:
            client = BrokerClient(url, self.secret_path)
            self.workbench.profile.data["name"] = "changed-profile"
            with self.assertRaisesRegex(WorkbenchError, "profile mismatch"):
                client.call("console_status")

    def test_callback_drain_tool_is_unavailable_in_shared_mode(self):
        with self.assertRaisesRegex(WorkbenchError, "broker-owned"):
            self.hub.call("ida", "debug_events", {})

    def test_shared_mcp_subprocess_end_to_end(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "session_state", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "analysis_status", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "memory_peek", "arguments": {"pid": 71, "address": "0x4000", "length": 4}}}
        ]
        with self.broker() as url:
            process = subprocess.run([sys.executable, "-m", "ps4_workbench", "--profile", str(self.profile_path),
                                      "serve", "--broker", url, "--token-file", str(self.secret_path)],
                                     input="".join(json.dumps(message) + "\n" for message in messages),
                                     capture_output=True, text=True, cwd=ROOT, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(len(responses), 4)
        self.assertEqual(json.loads(responses[-1]["result"]["content"][0]["text"])["hex"], "41414141")

    def test_shared_tool_cannot_bypass_disabled_permission(self):
        self.workbench.console.send_payload = Mock()
        with self.broker() as url:
            with self.assertRaisesRegex(WorkbenchError, "disabled"):
                BrokerClient(url, self.secret_path).call("payload_execute", manifest="anything", sha256="a" * 64)
        self.workbench.console.send_payload.assert_not_called()
