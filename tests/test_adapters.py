"""Python adapter side (ps4_workbench/) against the real native broker binary.

Build the binary first (``cargo build --locked``); set PS4_WORKBENCH_BIN to override.
"""
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

from ps4_workbench.adapters.base import LiveAnalysis
from ps4_workbench.agents import AnalysisWorker
from ps4_workbench.client import BrokerClient, load_token
from ps4_workbench.config import WorkbenchError, numeric, parse_address

ROOT = Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""


def workbench_binary():
    override = os.environ.get("PS4_WORKBENCH_BIN")
    candidates = [Path(override)] if override else [ROOT / "target" / kind / ("ps4-workbench" + EXE) for kind in ("debug", "release")]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("ps4-workbench binary not found; run `cargo build --locked` first")


class RustBroker:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ps4-adapter-test-")
        directory = Path(self.temporary.name)
        settings = json.loads((ROOT / "profiles/ps4-1400.json").read_text(encoding="utf-8"))
        settings.update(host="127.0.0.1", artifact_directory="artifacts", qualification_file="qualification.json")
        profile = directory / "profile.json"
        profile.write_text(json.dumps(settings), encoding="utf-8")
        self.token = directory / "broker-token.local"
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.process = subprocess.Popen([str(workbench_binary()), "--profile", str(profile), "broker", "--port", str(port),
                                         "--token-file", str(self.token)],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                if self.token.exists():
                    break
            except OSError:
                pass
            if time.monotonic() > deadline or self.process.poll() is not None:
                self.close()
                raise RuntimeError("Rust broker did not start")
            time.sleep(0.05)

    def client(self, name=None):
        return BrokerClient(self.url, self.token, name)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        self.temporary.cleanup()


class BrokerProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker()

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def start_worker(self, target, handler):
        worker = AnalysisWorker(self.broker.client(target + "-agent"), target, handler, "a" * 64).start()
        self.addCleanup(worker.stop)
        return worker

    def test_worker_serves_decompile_through_rust_broker(self):
        seen = []

        def handler(operation, arguments):
            seen.append((operation, arguments))
            return {"address": arguments["address"], "text": "return 42;", "truncated": False}

        self.start_worker("ida", handler)
        caller = self.broker.client("mcp")
        result = caller.call("analysis_decompile", target="ida", address="0x400100")
        self.assertEqual(result["text"], "return 42;")
        self.assertEqual(seen[0][0], "decompile")
        self.assertTrue(caller.call("analysis_status")["ida"]["connected"])

    def test_agent_exception_reaches_caller_instead_of_a_result(self):
        def fail(operation, arguments):
            raise RuntimeError("Decompiler unavailable")

        self.start_worker("ghidra", fail)
        with self.assertRaisesRegex(WorkbenchError, "Decompiler unavailable"):
            self.broker.client().call("analysis_decompile", target="ghidra", address="0x4000")

    def test_missing_agent_is_an_explicit_failure(self):
        with self.assertRaisesRegex(WorkbenchError, "No live iaito"):
            self.broker.client().call("analysis_functions", target="iaito")

    def test_second_agent_for_same_target_is_rejected(self):
        self.start_worker("binja", lambda operation, arguments: [])
        with self.assertRaises(WorkbenchError):
            self.broker.client("binja-intruder").request("agent_register", target="binja", program="b" * 64)

    def test_unregister_releases_target_for_a_new_agent(self):
        status = lambda: self.broker.client().call("analysis_status").get("iaito", {}).get("connected", False)
        worker = AnalysisWorker(self.broker.client("short-agent"), "iaito", lambda operation, arguments: [], "c" * 64).start()
        self.assertTrue(status())
        worker.stop()
        self.assertIsNone(worker.last_error)
        self.assertFalse(status())
        self.start_worker("iaito", lambda operation, arguments: [])
        self.assertTrue(status())

    def test_wrong_token_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / "token"
            wrong.write_text("f" * 64, encoding="ascii")
            with self.assertRaises(WorkbenchError):
                BrokerClient(self.broker.url, wrong)


class ClientValidationTests(unittest.TestCase):
    def test_only_loopback_http_broker_urls(self):
        for url in ("http://192.168.86.25:8765", "https://127.0.0.1:8765", "http://user@127.0.0.1:8765",
                    "http://127.0.0.1:8765/rpc"):
            with self.assertRaises(WorkbenchError, msg=url):
                BrokerClient(url, "unused")

    def test_token_file_must_be_64_lowercase_hex(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            for content in ("", "A" * 64, "a" * 63):
                path.write_text(content, encoding="ascii")
                with self.assertRaises(WorkbenchError):
                    load_token(path)
            path.write_text("a" * 64 + "\n", encoding="ascii")
            self.assertEqual(load_token(path), "a" * 64)

    def test_address_parsing_bounds(self):
        self.assertEqual(parse_address("0xffffffffffffffff"), 2 ** 64 - 1)
        self.assertEqual(parse_address("4096"), 4096)
        for bad in ("0x1" + "0" * 16, "zz", "", 5):
            with self.assertRaises(WorkbenchError):
                parse_address(bad)
        self.assertEqual(numeric("0x10"), 16)
        self.assertEqual(numeric(16), 16)


class LiveAnalysisTests(unittest.TestCase):
    def adapter(self, input_hash):
        adapter = LiveAnalysis.__new__(LiveAnalysis)
        adapter.client = Mock()
        adapter.input_hash = lambda: input_hash
        return adapter

    def test_live_read_refuses_mismatched_module(self):
        adapter = self.adapter("a" * 64)
        with self.assertRaisesRegex(WorkbenchError, "mismatch"):
            adapter.read_live(71, 0x100, 0x400000, 4, "b" * 64)
        adapter.client.call.assert_not_called()

    def test_live_read_rebases_and_rejects_short_reads(self):
        adapter = self.adapter("a" * 64)
        adapter.client.call.return_value = {"hex": "90909090"}
        self.assertEqual(adapter.read_live(71, 0x100, 0x400000, 4, "a" * 64), b"\x90" * 4)
        adapter.client.call.assert_called_once_with("memory_peek", pid=71, address="0x400100", length=4)
        adapter.client.call.return_value = {"hex": "90"}
        with self.assertRaisesRegex(WorkbenchError, "Short"):
            adapter.read_live(71, 0x100, 0x400000, 4, "a" * 64)


class WorkerTests(unittest.TestCase):
    def test_late_result_rejection_does_not_stop_worker(self):
        served = threading.Event()
        client = Mock()
        jobs = iter([{"id": "late", "operation": "functions", "arguments": {}},
                     {"id": "current", "operation": "functions", "arguments": {}}])

        def request(operation, **arguments):
            if operation == "agent_poll":
                return next(jobs, None)
            if operation == "agent_result":
                if arguments["identifier"] == "current":
                    served.set()
                return {"accepted": arguments["identifier"] == "current"}
            return {}

        client.request.side_effect = request
        worker = AnalysisWorker(client, "ida", lambda operation, arguments: [], "a" * 64).start()
        try:
            self.assertTrue(served.wait(5))
            self.assertFalse(worker.stopping.is_set())
            self.assertIn("expiration", worker.last_error)
        finally:
            worker.stop()


if __name__ == "__main__":
    unittest.main()
