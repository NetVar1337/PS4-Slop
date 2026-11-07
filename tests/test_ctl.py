"""Control-plane CLI (ps4_workbench/ctl.py) against the real native broker.

Build the binary first (``cargo build --locked``); set PS4_WORKBENCH_BIN to override.
"""
import contextlib
import io
import json
import unittest
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from ps4_workbench import ctl
from tests.test_adapters import RustBroker


class CtlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = RustBroker(toolset="full")
        cls.argv = ["--url", cls.broker.url, "--token-file", str(cls.broker.token)]

    @classmethod
    def tearDownClass(cls):
        cls.broker.close()

    def run_ctl(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ctl.main([*self.argv, *args])
        return code, out.getvalue(), err.getvalue()

    def test_status_and_tools(self):
        code, out, err = self.run_ctl("status")
        self.assertEqual(code, 0, err)
        self.assertIsInstance(json.loads(out), dict)

        code, out, err = self.run_ctl("tools")
        self.assertEqual(code, 0, err)
        text = json.dumps(json.loads(out))
        self.assertIn("project_export_offsets", text)
        # kernel_search requires the kernel_read permission, which the test
        # profile leaves disabled: it must stay hidden even under --toolset full.
        self.assertNotIn("kernel_search", text)

    def test_call_json_and_project_export_offsets(self):
        code, out, err = self.run_ctl("call", "project_open", json.dumps({"title_id": "CUSA00001", "name": "Ctl Game"}))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["project"]["id"], "CUSA00001")

        code, out, err = self.run_ctl("export-offsets")
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(result["format"], "ps4wb-offsets-v1")
        self.assertEqual(result["offsets"], 0)
        self.assertIn("header", result)
        self.assertIn("manifest", result)

    def test_gated_mutations_fail_closed_without_qualification(self):
        for args in (["payload-status", "--pid", "71"],
                     ["rpc", "--pid", "71", "--command", "1", "--argument", "0x5"],
                     ["config", "get", "--pid", "71", "--index", "0"],
                     ["config", "set", "--pid", "71", "--index", "0", "--value", "0x5"],
                     ["telemetry", "--pid", "71", "--index", "0"],
                     ["watch", "--pid", "71", "--count", "1"]):
            code, out, err = self.run_ctl(*args)
            self.assertEqual(code, 1, out)
            self.assertIn("error", err.lower())

    def test_invalid_payload_hash_is_rejected_before_any_call(self):
        code, out, err = self.run_ctl("stage", "--pid", "71", "--target", "t.json",
                                      "--payload", "p.elf", "--sha256", "not-a-hash")
        self.assertEqual(code, 1)
        self.assertIn("sha256", err)

    def rpc_fixture(self, root):
        root = Path(root)
        (root / "src/generated").mkdir(parents=True)
        (root / "workbench.json").write_text(json.dumps({
            "format": "ps4wb-scaffold-v1", "engine": "source", "payload": "payload.elf",
            "generated_directory": "src/generated", "rpc_version": 1, "staging": "immediate"}))
        sha = "a" * 64
        (root / "src/generated/rpc.json").write_text(json.dumps({
            "format": "ps4wb-rpc-v1", "rpc_version": 1, "module_sha256": sha,
            "features": [{"name": "paint", "bit": 1}, {"name": "menu", "bit": 2},
                         {"name": "diagnostics", "bit": 128}],
            "config": [{"name": "sensitivity", "index": 0, "type": "f32"},
                       {"name": "enabled", "index": 1, "type": "bool"}],
            "telemetry": [{"name": "active_features", "index": 2, "type": "u64", "role": "active_features"}]}))
        return str(root), sha

    def test_named_rpc_types_and_feature_names(self):
        with tempfile.TemporaryDirectory() as repo:
            repo, _ = self.rpc_fixture(repo)
            descriptor = ctl.load_rpc_descriptor(repo)
            self.assertEqual(ctl._feature_mask(descriptor, "paint,menu"), 3)
            self.assertEqual(ctl._feature_mask(descriptor, "safe"), 0)
            with self.assertRaises(Exception):
                ctl._feature_mask(descriptor, "unknown")
            floating = descriptor["config"][0]
            self.assertAlmostEqual(ctl._decode_rpc(floating, ctl._encode_rpc(floating, "1.5")), 1.5)
            boolean = descriptor["config"][1]
            self.assertEqual(ctl._encode_rpc(boolean, "true"), 1)
            self.assertTrue(ctl._decode_rpc(boolean, 1))

    def test_profile_roundtrip_mirror_confirmation_and_build_binding(self):
        with tempfile.TemporaryDirectory() as repo:
            repo, sha = self.rpc_fixture(repo)
            path = str(Path(repo) / "profile.json")
            args = SimpleNamespace(pid=71, project_dir=repo, path=path, features=None)
            with patch("ps4_workbench.ctl._call", side_effect=lambda client, name, **kw: {"raw": "0x5" if kw["command"] == 6 else kw["argument"]}):
                saved = ctl._profile_save(None, args)
            self.assertEqual(saved["features"], "0x5")
            self.assertEqual(saved["config_words"], 32)

            state = {"config": {}, "features": 0}
            writes = []
            def rpc(client, name, **kw):
                command = kw["command"]
                if command == 4:
                    state["config"][kw["argument"]] = kw["argument2"]
                    writes.append(kw)
                    return {"raw": "0x0"}
                if command == 5:
                    return {"raw": state["config"].get(kw["argument"], "0x0")}
                if command == 6:
                    return {"raw": hex(state["features"])}
                if command == 1:
                    state["features"] = int(kw["argument"], 0)
                    return {"raw": "0x0"}
                raise AssertionError(command)
            with patch("ps4_workbench.ctl._call", side_effect=rpc):
                loaded = ctl._profile_load(None, args)
            self.assertTrue(loaded["mirror_confirmed"])
            self.assertEqual(len(writes), 32)
            self.assertEqual(state["features"], 5)

            body = json.loads(Path(path).read_text())
            body["module_sha256"] = "b" * 64
            Path(path).write_text(json.dumps(body))
            with patch("ps4_workbench.ctl._call") as call:
                with self.assertRaisesRegex(Exception, "another module"):
                    ctl._profile_load(None, args)
                call.assert_not_called()

    def test_watch_requests_safe_features_once_per_stall(self):
        with tempfile.TemporaryDirectory() as repo:
            repo, _ = self.rpc_fixture(repo)
            args = SimpleNamespace(pid=71, project_dir=repo, safe_features="safe", interval=0.05, count=4)
            calls = []
            def rpc(client, name, **kw):
                calls.append((name, kw))
                if name == "payload_status":
                    return {"heartbeat": 7}
                return {"raw": "0x0"}
            with patch("ps4_workbench.ctl._call", side_effect=rpc), contextlib.redirect_stdout(io.StringIO()):
                ctl._watch(None, args)
            self.assertEqual(sum(name == "payload_rpc" and kw["command"] == 1 for name, kw in calls), 1)

    def test_update_dry_run_plans_both_games(self):
        code, out, err = self.run_ctl("update", "--game", "fortnite", "--pid", "71", "--dry-run")
        self.assertEqual(code, 0, err)
        plan = json.loads(out)
        self.assertEqual(plan["pipeline_recipe"], "unreal_pipeline")
        self.assertTrue(plan["dry_run"])

        code, out, err = self.run_ctl("update", "--game", "apex", "--pid", "71",
                                      "--old-artifact", "old.elf", "--annotations", "ann.json", "--dry-run")
        self.assertEqual(code, 0, err)
        plan = json.loads(out)
        self.assertEqual(plan["update_recipe"], "offset_refresh")
        self.assertEqual(plan["update_inputs"]["old_artifact"], "old.elf")


if __name__ == "__main__":
    unittest.main()
