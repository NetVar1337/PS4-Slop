import contextlib
import json
import threading
import time
from unittest.mock import Mock, patch

from ps4_workbench.agents import AnalysisAgents, AnalysisWorker
from ps4_workbench.client import BrokerClient, RemoteRegistry
from ps4_workbench.config import WorkbenchError

from .support import WorkbenchCase
from .test_broker import BrokerCase


class AgentTests(BrokerCase):
    def test_real_worker_and_broker_static_decompile(self):
        with self.broker() as url:
            agent_client = BrokerClient(url, self.secret_path, "ida-agent")
            worker = AnalysisWorker(agent_client, "ida", lambda operation, arguments: {"text": "return 42;", "operation": operation}, "a" * 64).start()
            try:
                registry = RemoteRegistry(BrokerClient(url, self.secret_path, "mcp"))
                result = registry.call("analysis_decompile", {"target": "ida", "address": "0x4000"})
                self.assertEqual(result["text"], "return 42;")
                self.assertTrue(registry.call("analysis_status", {})["ida"]["connected"])
            finally:
                worker.stop()

    def test_no_agent_is_an_explicit_failure(self):
        with self.assertRaisesRegex(WorkbenchError, "No live ghidra"):
            self.hub.call("mcp", "analysis_functions", {"target": "ghidra"})

    def test_only_readonly_allowlisted_analysis_operations(self):
        with self.assertRaisesRegex(WorkbenchError, "Unsupported"):
            AnalysisAgents().submit("ida", "eval", {"code": "anything"})
        with self.assertRaises(WorkbenchError):
            self.hub.call("mcp", "analysis_decompile", {"target": "ida", "address": "-1"})

    def test_active_agent_cannot_be_silently_replaced(self):
        agents = AnalysisAgents()
        agents.register("first", "ida", "program")
        with self.assertRaisesRegex(WorkbenchError, "already registered"):
            agents.register("second", "ida", "another")

    def test_foreign_agent_cannot_complete_job(self):
        agents = AnalysisAgents()
        agents.register("first", "ida", "program")
        agents.jobs["known"] = {"agent": "first", "done": threading.Event()}
        with self.assertRaisesRegex(WorkbenchError, "[Ff]oreign"):
            agents.complete("second", "known", result="fake")

    def test_timeout_removes_job_and_late_result_is_rejected(self):
        agents = AnalysisAgents()
        agents.register("first", "ida", "program")
        with self.assertRaisesRegex(WorkbenchError, "timed out"):
            agents.submit("ida", "functions", {}, timeout=0.01)
        self.assertEqual(agents.jobs, {})
        self.assertIsNone(agents.poll("first", "ida"))
        self.assertFalse(agents.complete("first", "expired", result="late")["accepted"])

    def test_agent_exception_is_reported_not_fabricated(self):
        def fail(operation, arguments):
            raise RuntimeError("Decompiler unavailable")
        with self.broker() as url:
            worker = AnalysisWorker(BrokerClient(url, self.secret_path, "agent"), "ghidra", fail, "hash").start()
            try:
                with self.assertRaisesRegex(WorkbenchError, "Decompiler unavailable"):
                    BrokerClient(url, self.secret_path).call("analysis_decompile", target="ghidra", address="0x4000")
            finally:
                worker.stop()

    def test_late_job_result_does_not_kill_analysis_worker(self):
        finished = threading.Event()
        client = Mock()
        jobs = iter([{"id": "late", "operation": "functions", "arguments": {}},
                     {"id": "current", "operation": "functions", "arguments": {}}])

        def request(operation, **arguments):
            if operation == "agent_poll":
                return next(jobs, None)
            if operation == "agent_result":
                if arguments["identifier"] == "late":
                    return {"accepted": False}
                finished.set()
                return {"accepted": True}
            return {}
        client.request.side_effect = request
        worker = AnalysisWorker(client, "ida", lambda operation, arguments: [], "hash").start()
        try:
            self.assertTrue(finished.wait(3))
            self.assertFalse(worker.stopping.is_set())
        finally:
            worker.stop()


class ExtractionTests(WorkbenchCase):
    @contextlib.contextmanager
    def ftp_fixture(self, files):
        client = Mock()

        def retrieve(command, callback):
            callback(files[command.removeprefix("RETR ")])
        client.retrbinary.side_effect = retrieve
        with patch.object(self.workbench.console, "ftp") as ftp:
            ftp.return_value.__enter__.return_value = client
            yield client

    def test_multi_file_extraction_retains_paths_and_hashes(self):
        with self.ftp_fixture({"/data/a": b"one", "/data/b": b"two"}):
            result = self.workbench.console.ftp_extract(["/data/a", "/data/b"])
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_bytes"], 6)
        manifest = json.loads(self.workbench.store.read(result["manifest"]["path"]))
        self.assertEqual(manifest["files"][0]["metadata"]["remote_path"], "/data/a")

    def test_extraction_budget_failure_is_partial_not_success(self):
        self.settings["limits"]["transfer_bytes"] = 5
        self.reload()
        with self.ftp_fixture({"/data/a": b"one", "/data/b": b"two"}):
            result = self.workbench.console.ftp_extract(["/data/a", "/data/b"])
        self.assertFalse(result["complete"])
        self.assertEqual(len(result["files"]), 1)
        self.assertIn("limit", result["error"])

    def test_duplicate_and_traversal_paths_rejected_before_network(self):
        with patch.object(self.workbench.console, "ftp") as ftp:
            for paths in (["/data/a", "/data/a"], ["/data/../x"], []):
                with self.assertRaises(WorkbenchError):
                    self.workbench.console.ftp_extract(paths)
            ftp.assert_not_called()

    def test_region_dump_chunks_and_keeps_provenance(self):
        self.settings["limits"]["memory_bytes"] = 4
        self.reload()
        debugger = self.workbench.debugger
        debugger.maps = Mock(return_value=[{"start": 0x1000, "end": 0x2000, "protection": 1}])
        debugger.process_info = Mock(return_value={"pid": 71})
        debugger.read_memory = Mock(side_effect=lambda pid, address, length: b"X" * length)
        result = self.workbench.region_dump(71, 0x1000, 10)
        self.assertTrue(result["complete"])
        self.assertEqual([call.args[2] for call in debugger.read_memory.call_args_list], [4, 4, 2])
        self.assertEqual(self.workbench.store.read(result["artifact"]["path"]), b"X" * 10)

    def test_region_dump_preserves_partial_capture(self):
        self.settings["limits"]["memory_bytes"] = 4
        self.reload()
        debugger = self.workbench.debugger
        debugger.maps = Mock(return_value=[{"start": 0x1000, "end": 0x2000, "protection": 1}])
        debugger.process_info = Mock(return_value={"pid": 71})
        debugger.read_memory = Mock(side_effect=[b"AAAA", WorkbenchError("EOF")])
        result = self.workbench.region_dump(71, 0x1000, 10)
        self.assertFalse(result["complete"])
        self.assertEqual(self.workbench.store.read(result["artifact"]["path"]), b"AAAA")

    def test_region_dump_rejects_mapping_gap_before_read(self):
        debugger = self.workbench.debugger
        debugger.maps = Mock(return_value=[{"start": 0x1000, "end": 0x1004, "protection": 1},
                                          {"start": 0x1008, "end": 0x1010, "protection": 1}])
        debugger.read_memory = Mock()
        with self.assertRaisesRegex(WorkbenchError, "unmapped"):
            self.workbench.region_dump(71, 0x1000, 12)
        debugger.read_memory.assert_not_called()
