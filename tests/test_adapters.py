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
from types import SimpleNamespace
from unittest.mock import Mock

from ps4_workbench.adapters.base import APPLY_OPERATIONS, ApplyMixin, LiveAnalysis, Unsupported, struct_c_declaration
from ps4_workbench.agents import AnalysisWorker
from ps4_workbench.client import BrokerClient, load_token
from ps4_workbench.config import WorkbenchError, numeric, parse_address
from ps4_workbench.adapters.binja import BinjaWorkbench

ROOT = Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""


class BinaryNinjaAdapterTests(unittest.TestCase):
    def adapter(self, bv):
        adapter = object.__new__(BinjaWorkbench)
        adapter.bv = bv
        adapter.expected_program_hash = None
        return adapter

    def test_hash_uses_original_input_not_bndb_database(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "eboot.bin"
            database = Path(directory) / "eboot.bndb"
            original.write_bytes(b"original module")
            database.write_bytes(b"analysis database contents")
            adapter = self.adapter(SimpleNamespace(file=SimpleNamespace(
                filename=str(database), original_filename=str(original)
            )))
            import hashlib
            self.assertEqual(adapter.input_hash(), hashlib.sha256(b"original module").hexdigest())

            adapter.bv.file.original_filename = str(database)
            with self.assertRaisesRegex(WorkbenchError, "cannot identify the original module"):
                adapter.input_hash()

    def test_decompile_resolves_function_containing_address_with_bn6_api(self):
        function = SimpleNamespace(start=0x1000, hlil="return 42;", mlil=None, llil=None)

        class FakeBinaryView:
            file = SimpleNamespace(original_filename=None)

            def get_function_at(self, address):
                return None

            def get_functions_containing(self, address):
                self.queried = address
                return [function]

        bv = FakeBinaryView()
        adapter = self.adapter(bv)
        adapter.input_hash = lambda: "a" * 64
        result = adapter.analyze("decompile", {"address": "0x1010"})
        self.assertEqual(bv.queried, 0x1010)
        self.assertEqual(result["address"], "0x1000")
        self.assertEqual(result["text"], "return 42;")


def workbench_binary():
    override = os.environ.get("PS4_WORKBENCH_BIN")
    candidates = [Path(override)] if override else [ROOT / "target" / kind / ("ps4-workbench" + EXE) for kind in ("debug", "release")]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("ps4-workbench binary not found; run `cargo build --locked` first")


class RustBroker:
    def __init__(self, toolset="read-only"):
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
        self.process = subprocess.Popen([str(workbench_binary()), "--profile", str(profile), "--toolset", toolset,
                                         "broker", "--port", str(port),
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


class FakeAnalyzer(ApplyMixin):
    """In-memory analyzer database implementing the apply primitives (no IDA/Ghidra required)."""

    def __init__(self, base=0x400000, color=True):
        self.base, self.color = base, color
        self.names, self.comments, self.types, self.structs, self.colors = {}, {}, {}, {}, {}
        self.functions = {"sceKernelUsleep": 0x401000, "1jfXLRVzisc": 0x401100}

    def image_base(self):
        return self.base

    def find_function(self, name):
        return self.functions.get(name)

    def has_user_type(self, handle):
        return handle in self.types

    def set_prototype(self, handle, declaration):
        if "(" not in declaration:
            return False
        self.types[handle] = declaration
        return True

    def name_at(self, address):
        return self.names.get(address, "sub_%x" % address)

    def set_name(self, address, name):
        self.names[address] = name
        return True

    def comment_at(self, address):
        return self.comments.get(address)

    def set_comment(self, address, text):
        if text:
            self.comments[address] = text
        else:
            self.comments.pop(address, None)
        return True

    def type_exists(self, name):
        return name in self.structs

    def define_struct(self, struct, declaration):
        self.structs[struct["name"]] = struct_c_declaration(struct)
        return True

    def color_block(self, address, size, rgb):
        if not self.color:
            raise Unsupported("color")
        if rgb is None:
            self.colors.pop(address, None)
        else:
            self.colors[address] = rgb
        return True


class ApplyMixinTests(unittest.TestCase):
    def test_symbols_respect_user_names_overwrite_and_unnamed_only(self):
        fake = FakeAnalyzer()
        fake.names[0x400010] = "user_name"
        report = fake.apply("apply_symbols", {"symbols": [
            {"rva": "0x10", "name": "ported"},
            {"rva": "0x20", "name": "fresh", "comment": "from port"},
            {"address": "0x400030", "name": "Foo::vf0", "only_if_unnamed": True}], "overwrite": False})
        self.assertEqual((report["applied"], report["skipped"]), (2, 1))
        self.assertEqual(fake.names[0x400010], "user_name")
        self.assertEqual(fake.names[0x400020], "fresh")
        self.assertEqual(fake.comments[0x400020], "from port")
        fake.apply("apply_symbols", {"symbols": [{"rva": "0x10", "name": "ported"}], "overwrite": True})
        self.assertEqual(fake.names[0x400010], "ported")
        fake.apply("apply_symbols", {"symbols": [{"rva": "0x10", "name": "vf", "only_if_unnamed": True}], "overwrite": True})
        self.assertEqual(fake.names[0x400010], "ported")

    def test_prototypes_match_names_then_nids_and_keep_user_types(self):
        fake = FakeAnalyzer()
        fake.types[0x401100] = "int existing(void)"
        report = fake.apply("apply_prototypes", {"overwrite": False, "prototypes": [
            {"name": "sceKernelUsleep", "declaration": "int sceKernelUsleep(unsigned int usec)"},
            {"name": "sceKernelGetpid", "nid": "1jfXLRVzisc", "declaration": "int sceKernelGetpid(void)"},
            {"name": "missing", "declaration": "void missing(void)"}]})
        self.assertEqual((report["applied"], report["skipped"]), (1, 2))
        self.assertEqual(fake.types[0x401000], "int sceKernelUsleep(unsigned int usec)")
        report = fake.apply("apply_prototypes", {"overwrite": True, "prototypes": [
            {"name": "sceKernelGetpid", "nid": "1jfXLRVzisc", "declaration": "int sceKernelGetpid(void)"}]})
        self.assertEqual(report["applied"], 1)

    def test_struct_declaration_pads_and_existing_types_are_kept(self):
        struct = {"name": "Player", "size": 24, "fields": [
            {"offset": 0, "size": 8, "name": "vtable", "type": "void *"},
            {"offset": 12, "size": 4, "name": "health", "type": "float"},
            {"offset": 16, "size": 3, "name": "flags"}]}
        text = struct_c_declaration(struct)
        self.assertIn("unsigned char _pad_8[4];", text)
        self.assertIn("float health;", text)
        self.assertIn("unsigned char flags[3];", text)
        self.assertIn("unsigned char _pad_13[5];", text)
        self.assertIn("unsigned int health;", struct_c_declaration(struct, typed=False))
        fake = FakeAnalyzer()
        self.assertEqual(fake.apply("apply_struct", {"struct": struct, "overwrite": False})["applied"], 1)
        self.assertEqual(fake.apply("apply_struct", {"struct": struct, "overwrite": False})["skipped"], 1)
        self.assertEqual(fake.apply("apply_struct", {"struct": struct, "overwrite": True})["fields"], 3)

    def test_coverage_colours_comments_clears_and_reports_unsupported(self):
        fake = FakeAnalyzer()
        blocks = [{"rva": "0x100", "size": 8, "hits": 4}, {"rva": "0x200", "size": 4, "hits": 1}]
        report = fake.apply("apply_coverage", {"blocks": blocks, "color": "0x00ff00", "comment": True, "clear": False})
        self.assertEqual(report["applied"], 2)
        self.assertEqual(fake.colors[0x400100], 0x00FF00)
        self.assertEqual(fake.comments[0x400100], "PS4 coverage hits=4")
        fake.comments[0x400200] = "keep user comment"
        fake.apply("apply_coverage", {"blocks": blocks, "color": "0x00ff00", "comment": True, "clear": True})
        self.assertEqual(fake.colors, {})
        self.assertNotIn(0x400100, fake.comments)
        self.assertEqual(fake.comments[0x400200], "keep user comment")

        no_color = FakeAnalyzer(color=False)
        report = no_color.apply("apply_coverage", {"blocks": blocks, "color": "0x00ff00", "comment": True, "clear": False})
        self.assertEqual(report["unsupported"], ["color"])
        self.assertEqual(report["applied"], 2)
        with self.assertRaisesRegex(WorkbenchError, "color is unsupported"):
            no_color.apply("apply_coverage", {"blocks": blocks, "color": "0x00ff00", "comment": False, "clear": False})

    def test_base_adapter_marks_everything_unsupported(self):
        bare = ApplyMixin()
        with self.assertRaisesRegex(WorkbenchError, "unsupported"):
            bare.apply("apply_symbols", {"symbols": [{"address": "0x10", "name": "x"}]})
        with self.assertRaisesRegex(WorkbenchError, "unsupported"):
            bare.apply("apply_prototypes", {"prototypes": [{"name": "x", "declaration": "int x(void)"}]})
        self.assertTrue(set(APPLY_OPERATIONS) >= {"apply_coverage", "apply_struct"})


class ApplyThroughBrokerTests(unittest.TestCase):
    """analysis_apply_* end to end: Rust broker validates/rebases artifacts, a fake agent applies them."""

    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker()
        cls.artifacts = Path(cls.broker.temporary.name) / "artifacts"
        cls.artifacts.mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def write(self, name, document):
        (self.artifacts / name).write_text(json.dumps(document), encoding="utf-8")
        return name

    def serve(self, fake, program="e" * 64):
        def handler(operation, arguments):
            if operation in APPLY_OPERATIONS:
                return fake.apply(operation, arguments)
            raise WorkbenchError("unexpected operation " + operation)
        worker = AnalysisWorker(self.broker.client("ida-apply-agent"), "ida", handler, program).start()
        self.addCleanup(worker.stop)
        return self.broker.client("mcp-apply")

    def test_coverage_classes_prototypes_struct_and_symbols(self):
        fake = FakeAnalyzer(base=0x10000)
        caller = self.serve(fake)
        coverage = self.write("coverage-a.json", {"format": "ps4wb-coverage-v1", "module": "eboot.bin", "module_sha256": "e" * 64,
                                                  "image_base": "0x7f0000000", "blocks": [{"rva": "0x40", "size": 8, "hits": 2}]})
        report = caller.call("analysis_apply_coverage", target="ida", artifact=coverage, static_base="0x400000", comment=True)
        self.assertEqual(report["applied"], 1)
        self.assertEqual(report["module_hash_matches"], True)
        self.assertEqual(fake.colors[0x400040], 0xC8F0C8)

        classes = self.write("classes-a.json", {"format": "ps4wb-classes-v1", "image_base": "0x0", "classes": [
            {"name": "Player", "mangled": "6Player", "typeinfo": "0x900", "vtable": "0x800", "bases": [],
             "virtuals": [{"index": 0, "target": "0x100"}, {"index": 1, "target": "0x180"}]}]})
        fake.names[0x10180] = "Player_update"
        report = caller.call("analysis_apply_classes", target="ida", artifact=classes)
        self.assertEqual(report["items"], 4)
        self.assertEqual(fake.names[0x10800], "vtable_for_Player")
        self.assertEqual(fake.names[0x10100], "Player::vf0")
        self.assertEqual(fake.names[0x10180], "Player_update")

        prototypes = self.write("prototypes-a.json", {"format": "ps4wb-prototypes-v1", "prototypes": [
            {"name": "sceKernelUsleep", "nid": "1jfXLRVzisc", "library": "libkernel", "declaration": "int sceKernelUsleep(unsigned int)",
             "return": "int", "params": [{"name": "usec", "type": "unsigned int"}], "source": "test"}]})
        self.assertEqual(caller.call("analysis_apply_prototypes", target="ida", artifact=prototypes)["applied"], 1)

        struct = self.write("struct-a.json", {"format": "ps4wb-struct-v1", "name": "Player", "size": 8,
                                              "fields": [{"offset": 0, "size": 4, "name": "hp", "type": "int", "evidence": "w"}]})
        self.assertEqual(caller.call("analysis_apply_struct", target="ida", artifact=struct)["applied"], 1)
        self.assertIn("int hp;", fake.structs["Player"])

        report = caller.call("analysis_apply_symbols", target="ida", symbols={"0x20": "tick"})
        self.assertEqual(report["applied"], 1)
        self.assertEqual(fake.names[0x10020], "tick")

    def test_broker_refuses_foreign_module_and_bad_artifacts_before_the_agent(self):
        fake = FakeAnalyzer()
        caller = self.serve(fake)
        foreign = self.write("coverage-b.json", {"format": "ps4wb-coverage-v1", "module_sha256": "f" * 64,
                                                 "blocks": [{"rva": "0x40", "size": 8, "hits": 2}]})
        with self.assertRaisesRegex(WorkbenchError, "module_sha256"):
            caller.call("analysis_apply_coverage", target="ida", artifact=foreign)
        with self.assertRaisesRegex(WorkbenchError, "expected ps4wb-struct-v1"):
            caller.call("analysis_apply_struct", target="ida", artifact=foreign)
        with self.assertRaises(WorkbenchError):
            caller.call("analysis_apply_coverage", target="ida", artifact="../outside.json")
        self.assertEqual(fake.colors, {})


class ProjectAndRecipeThroughBrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker(toolset="full")

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def test_project_index_and_recipe_catalog(self):
        caller = self.broker.client("mcp-project")
        # BrokerClient.call(name, **arguments) reserves "name"; send the envelope directly.
        opened = caller.request("call", name="project_open", arguments={"title_id": "CUSA00001", "app_version": "01.00", "name": "Test"})
        self.assertEqual(opened["project"]["id"], "CUSA00001-v01_00")
        caller.call("project_record", notes=["first look"], questions=[{"text": "Where is the save key?"}], tags=["triage"])
        summary = caller.call("project_summary")
        self.assertEqual(summary["open_questions"]["count"], 1)
        self.assertEqual(caller.call("project_query", tag="triage")["total"], 2)
        names = [recipe["name"] for recipe in caller.call("recipe_list")["recipes"]]
        self.assertIn("dump_and_rebuild", names)
        with self.assertRaisesRegex(WorkbenchError, "debug lease"):
            caller.call("recipe_run", recipe="crash_capture", inputs={"pid": 5})


if __name__ == "__main__":
    unittest.main()
