"""Control-plane CLI (ps4_workbench/ctl.py) against the real native broker.

Build the binary first (``cargo build --locked``); set PS4_WORKBENCH_BIN to override.
"""
import contextlib
import io
import json
import unittest
from pathlib import Path

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
