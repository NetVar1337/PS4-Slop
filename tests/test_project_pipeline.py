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
        generated = project / "src/generated"
        install = json.loads((generated / "install.json").read_text())
        self.assertEqual(install["format"], "ps4wb-installed-v1")
        self.assertEqual(install["module_sha256"], sha)
        checked = subprocess.run([sys.executable, str(project / "build.py"), "--check-generated"],
                                 capture_output=True, text=True, timeout=120)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        config = generated / "engine_config.hpp"
        original = config.read_bytes()
        try:
            config.write_bytes(original + b"// partial install\n")
            rejected = subprocess.run([sys.executable, str(project / "build.py"), "--check-generated"],
                                      capture_output=True, text=True, timeout=120)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("rerun project_install", rejected.stdout + rejected.stderr)
        finally:
            config.write_bytes(original)
        output = subprocess.run([sys.executable, str(project / "build.py"), "--host-test"], capture_output=True, text=True, timeout=120)
        self.assertEqual(output.returncode, 0, output.stdout + output.stderr)
        # Optional local SDK check: collect the actual ELF and its source evidence.
        sdk_root = Path(os.environ.get("OO_PS4_TOOLCHAIN", str(Path.home() / ".local/openorbis-ps4-toolchain")))
        if (sdk_root / "link.x").is_file():
            evidence = build(project, [sys.executable, "build.py", "--sdk", str(sdk_root)], "build/payload.elf")
            collected = self.call("project_collect_build")
            self.assertEqual(collected["payload"]["sha256"], evidence["payload"]["sha256"])
            self.assertFalse(collected["deployed"])



class GameScaffoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker(toolset="full")

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def call(self, tool, **arguments):
        return self.broker.client().request("call", name=tool, arguments=arguments)

    def test_game_new_emits_repo_shaped_project_and_verify_runs(self):
        parent = tempfile.TemporaryDirectory(prefix="ps4-game-new-")
        self.addCleanup(parent.cleanup)
        self.call("game_new", name="ExamplePS4", engine="source",
                  directory=parent.name, title_id="CUSA12552", payload="build/game.elf")
        repo = Path(parent.name) / "ExamplePS4"
        descriptor = json.loads((repo / "workbench.json").read_text())
        self.assertEqual(descriptor["engine"], "source")
        self.assertEqual(descriptor["payload"], "build/game.elf")
        self.assertEqual(descriptor["rpc_version"], 1)
        makefile = (repo / "Makefile").read_text()
        self.assertIn("templates/payload/orbis.mk", makefile)
        self.assertIn("-DPS4WB_ENGINE_SOURCE", makefile)
        self.assertIn("inject", makefile)
        self.assertTrue((repo / "src/features.hpp").is_file())
        self.assertTrue((repo / "offsets/README.md").is_file())
        self.assertTrue((repo / "include/internals/runtime.hpp").is_file())
        output = subprocess.run([sys.executable, str(repo / "build.py"), "--host-test", "--engine", "source"],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(output.returncode, 0, output.stdout + output.stderr)
        # Duplicate scaffolding is refused.
        with self.assertRaises(Exception):
            self.call("game_new", name="ExamplePS4", engine="source", directory=parent.name)
        # Read-only verification works once a project is open.
        self.call("project_open", title_id="CUSA12552", app_version="01.00", name="ExamplePS4")
        verified = self.call("game_verify")
        self.assertIn("doctor", verified)
        self.assertIn("summary", verified)
        self.assertFalse(verified["hardware_verified"])
        recipe = json.loads((repo / "recipe.json").read_text())
        self.assertEqual(recipe["commands"][0][-2:], ["--output", "build/game.elf"])
        sdk_root = Path(os.environ.get("OO_PS4_TOOLCHAIN", str(Path.home() / ".local/openorbis-ps4-toolchain")))
        if (sdk_root / "link.x").is_file():
            output = subprocess.run([sys.executable, str(repo / "build.py"), "--engine", "source",
                                     "--output", descriptor["payload"]], cwd=repo,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(output.returncode, 0, output.stdout + output.stderr)
            self.assertTrue((repo / descriptor["payload"]).is_file())
        checked = self.call("game_verify", repository=str(repo), host_tests=True,
                            cross_build=(sdk_root / "link.x").is_file())
        self.assertTrue(checked["checks"]["host_test"]["success"], checked)
        if (sdk_root / "link.x").is_file():
            self.assertTrue(checked["checks"]["cross_build"]["success"], checked)
        self.assertTrue(checked["next_actions"])


class DescriptorDrivenUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker(toolset="full")

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def test_load_descriptor_reads_workbench_json(self):
        from ps4_workbench.ctl import load_descriptor
        with tempfile.TemporaryDirectory() as empty:
            self.assertIsNone(load_descriptor(empty))
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "workbench.json").write_text(json.dumps({
                "format": "ps4wb-scaffold-v1", "engine": "unreal", "payload": "payload.elf",
                "generated_directory": "src/generated", "rpc_version": 1, "staging": "immediate"}))
            descriptor = load_descriptor(repo)
            assert descriptor is not None
            self.assertEqual(descriptor["engine"], "unreal")
            (Path(repo) / "workbench.json").write_text(json.dumps({"format": "other"}))
            with self.assertRaises(WorkbenchError):
                load_descriptor(repo)

    def test_update_delegates_research_to_game_update(self):
        from unittest.mock import patch
        from ps4_workbench import ctl
        client = self.broker.client()
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "workbench.json").write_text(json.dumps({
                "format": "ps4wb-scaffold-v1", "engine": "unreal", "payload": "payload.elf",
                "generated_directory": "src/generated", "rpc_version": 1, "staging": "immediate"}))
            argv = ["--url", self.broker.url, "--token-file", str(self.broker.token),
                    "update", "--project-dir", repo, "--pid", "71", "--no-build"]
            parsed = ctl.build_parser().parse_args(argv)
            result = {"session": "a" * 32, "target": "target.json", "installed": None}
            with patch("ps4_workbench.ctl._call", return_value=result) as call:
                returned = ctl._update(client, parsed)
            self.assertEqual(call.call_args.args[1], "game_update")
            self.assertEqual(call.call_args.kwargs["repository"], str(Path(repo).resolve()))
            self.assertEqual(call.call_args.kwargs["engine"], "unreal")
            self.assertEqual(returned["session"], "a" * 32)

    def test_update_dry_run_derives_plan_from_workbench_json(self):
        from ps4_workbench import ctl
        client = self.broker.client()
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "workbench.json").write_text(json.dumps({
                "format": "ps4wb-scaffold-v1", "engine": "unreal", "payload": "payload.elf",
                "generated_directory": "src/generated", "rpc_version": 1, "staging": "immediate"}))
            argv = ["--url", self.broker.url, "--token-file", str(self.broker.token),
                    "update", "--project-dir", repo, "--pid", "71", "--dry-run"]
            plan = ctl._update(client, ctl.build_parser().parse_args(argv))
            self.assertEqual(plan["engine"], "unreal")
            self.assertEqual(plan["pipeline_recipe"], "unreal_pipeline")
            self.assertEqual(plan["payload_repo"], str(Path(repo).resolve()))
            self.assertEqual(plan["inputs"]["status_magic"], "0x5053494e")
            self.assertTrue(plan["dry_run"])
            # Update path ports annotations through the engine update recipe.
            argv += ["--old-artifact", "old.elf", "--annotations", "ann.json"]
            plan = ctl._update(client, ctl.build_parser().parse_args(argv))
            self.assertEqual(plan["update_recipe"], "offset_refresh")
            self.assertEqual(plan["update_inputs"]["old_artifact"], "old.elf")
        # Named games still work without a descriptor.
        argv = ["--url", self.broker.url, "--token-file", str(self.broker.token),
                "update", "--game", "apex", "--pid", "71", "--dry-run"]
        plan = ctl._update(client, ctl.build_parser().parse_args(argv))
        self.assertEqual(plan["game"], "apex")
        self.assertEqual(plan["engine"], "source")
        self.assertEqual(plan["pipeline_recipe"], "source_pipeline")
        # Neither --game nor a descriptor is an error.
        with tempfile.TemporaryDirectory() as empty:
            argv = ["--url", self.broker.url, "--token-file", str(self.broker.token),
                    "update", "--project-dir", empty, "--pid", "71", "--dry-run"]
            with self.assertRaises(WorkbenchError):
                ctl._update(client, ctl.build_parser().parse_args(argv))


if __name__ == "__main__":
    unittest.main()
