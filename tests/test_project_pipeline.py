"""Real generated-project builds and bounded local build-runner failures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ps4_workbench.build import build, source_snapshot
from ps4_workbench.config import WorkbenchError
from tests.test_adapters import RustBroker


class LocalBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ps4-build-tests-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()

    def writer(self):
        script = self.repo / "build_fixture.py"
        script.write_text("from pathlib import Path\nb=bytearray(64)\nb[:7]=b'\\x7fELF\\x02\\x01\\x01'\nb[16:18]=(3).to_bytes(2,'little')\nb[18:20]=(62).to_bytes(2,'little')\nPath('payload.elf').write_bytes(b)\n")
        return [sys.executable, str(script)]

    def test_build_records_source_hashes_and_archives_existing_output(self):
        argv = self.writer()
        first = build(self.repo, argv, "payload.elf")
        second = build(self.repo, argv, "payload.elf")
        self.assertEqual(first["payload"]["sha256"], second["payload"]["sha256"])
        self.assertTrue((self.repo / "build/archive" / (first["payload"]["sha256"] + ".elf")).is_file())
        self.assertTrue((self.repo / "workbench.lock.json").is_file())

    def test_noop_build_cannot_reuse_a_stale_output(self):
        build(self.repo, self.writer(), "payload.elf")
        with self.assertRaisesRegex(WorkbenchError, "fresh"):
            build(self.repo, [sys.executable, "-c", "pass"], "payload.elf")

    def test_timeout_logs_and_path_bounds(self):
        with self.assertRaisesRegex(WorkbenchError, "bounds"):
            build(self.repo, [sys.executable, "-c", "import time; time.sleep(10)"], "payload.elf", timeout=0.1)
        with self.assertRaisesRegex(WorkbenchError, "bounds"):
            build(self.repo, [sys.executable, "-c", "print('x'*100000)"], "payload.elf", max_log=1024)
        with self.assertRaisesRegex(WorkbenchError, "escapes"):
            build(self.repo, [sys.executable, "-c", "pass"], "../outside.elf")

    def test_snapshot_ignores_build_outputs_but_detects_source_changes(self):
        source = self.repo / "source.cpp"
        source.write_text("int value=1;")
        first = source_snapshot(self.repo)
        (self.repo / "build").mkdir()
        (self.repo / "build/output.json").write_text("{}")
        self.assertEqual(source_snapshot(self.repo), first)
        source.write_text("int value=2;")
        self.assertNotEqual(source_snapshot(self.repo), first)


class GeneratedProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker(toolset="full")

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def call(self, tool, **arguments):
        return self.broker.client().request("call", name=tool, arguments=arguments)

    def test_all_engine_scaffolds_compile_and_run_the_real_runtime(self):
        artifact_root = Path(self.broker.temporary.name) / "artifacts"
        for engine in ("generic", "unreal", "source"):
            with self.subTest(engine=engine):
                result = self.call("payload_scaffold", name="smoke-" + engine, engine=engine)
                project = artifact_root / result["project"]
                output = subprocess.run([sys.executable, str(project / "build.py"), "--host-test"], capture_output=True, text=True, timeout=120)
                self.assertEqual(output.returncode, 0, output.stdout + output.stderr)
                descriptor = json.loads((project / "workbench.json").read_text())
                self.assertEqual(descriptor["engine"], engine)
                self.assertEqual(descriptor["rpc_version"], 1)

    def test_session_cli_persists_progress_and_cancellation(self):
        self.call("project_open", title_id="CUSA11223", app_version="01.00")
        created = self.call("recipe_session", action="create", definition={
            "format": "ps4wb-recipe-v1", "name": "offline", "inputs": {},
            "steps": [{"tool": "console_status", "arguments": {}}]})
        status = self.call("recipe_session", action="advance", session=created["id"])
        self.assertEqual(status["state"], "completed")
        cancelled = self.call("recipe_session", action="cancel", session=created["id"])
        self.assertEqual(cancelled["state"], "cancelled")

    def test_install_consumes_a_bound_sdk_with_a_custom_namespace(self):
        artifact_root = Path(self.broker.temporary.name) / "artifacts"
        result = self.call("payload_scaffold", name="integrated-unreal", engine="unreal")
        project = artifact_root / result["project"]
        self.call("project_open", title_id="CUSA44556", app_version="01.00", name="Integrated fixture")
        sha = "a" * 64
        self.call("project_record", modules=[{"name": "eboot.bin", "sha256": sha}])
        self.call("project_manifest", manifest={"format": "ps4wb-project-v1", "title_id": "CUSA44556", "app_version": "01.00",
                  "module_sha256": sha, "engine": "unreal", "sdk": "openorbis", "source_commit": "b" * 40,
                  "repository": str(project), "staging": "immediate", "rpc_version": 1})
        (artifact_root / "fixture-engine.json").write_text(json.dumps({"format": "ps4wb-unreal-v1", "image_base": "0x400000",
            "gobjects": {"address": "0x402000", "layout": "FChunkedFixedUObjectArray"},
            "gnames": {"address": "0x401000", "blocks": "0x401000", "kind": "FNamePool"},
            "offsets": {"objobjects": 16, "item_size": 24, "object_name": 24}, "sdk": []}))
        sdk = self.call("engine_sdk_export", unreal="fixture-engine.json", namespace="fortnite", module_sha256=sha)
        (artifact_root / "fixture-target.json").write_text(json.dumps({"format": "ps4wb-internals-target-v1", "title_id": "CUSA44556",
            "module_sha256": sha, "image_base": "0x400000", "fingerprints": [{"address": "0x400100", "hex": "9090"}]}))
        self.call("project_install", target="fixture-target.json", engine=sdk["artifact"]["path"])
        output = subprocess.run([sys.executable, str(project / "build.py"), "--host-test"], capture_output=True, text=True, timeout=120)
        self.assertEqual(output.returncode, 0, output.stdout + output.stderr)
        # Optional local SDK check: collect the actual ELF and its source evidence.
        sdk_root = Path(os.environ.get("OO_PS4_TOOLCHAIN", str(Path.home() / ".local/openorbis-ps4-toolchain")))
        if (sdk_root / "link.x").is_file():
            evidence = build(project, [sys.executable, "build.py", "--sdk", str(sdk_root)], "build/payload.elf")
            collected = self.call("project_collect_build")
            self.assertEqual(collected["payload"]["sha256"], evidence["payload"]["sha256"])
            self.assertFalse(collected["deployed"])


if __name__ == "__main__":
    unittest.main()
