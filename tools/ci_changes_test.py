"""Regression cases for cheap, conservative CI selection."""

import os
import subprocess
import unittest
from unittest.mock import patch

from ci_changes import SUITES, affected, changed_paths


class SelectionTest(unittest.TestCase):
    def test_dependency_map(self):
        cases = {
            "README.md": set(),
            "notes/intel-x86-semantic-source-union-census-2026-09-04.md": set(),
            "artifacts/golden/README.md": set(),
            "artifacts/golden/unexpected.md": {"golden", "lean"},
            "artifacts/golden/2_add.model.json.zst": {"golden", "lean"},
            "extractor/typed_z3.py": {"lint", "au", "differential"},
            "antiunification/algebra.py": {"lint", "au"},
            "Ixyk/QfAbv/Semantics.lean": {"lean", "differential"},
            "tools/ci_lean.py": {"lint", "lean"},
            "tools/lean_differential.py": {"lint", "differential"},
            "tools/ci_golden.py": {"lint", "golden"},
            "catalog/x86_64_probes.json": {"lint", "golden", "au"},
            "MODULE.bazel.lock": {"lint", "au"},
            "flake.lock": SUITES,
            "flake.nix": SUITES,
            ".github/actions/changes/action.yml": SUITES,
            "tools/ci_changes.py": SUITES,
            "unknown/new-input.json": SUITES,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(affected([path]), expected)

    def test_union_and_empty(self):
        self.assertEqual(affected([]), set())
        self.assertEqual(
            affected(["README.md", "extractor/artifact.py"]),
            {"lint", "au", "differential"},
        )

    def test_manual_missing_and_initial_push_run_all(self):
        for event, base in [
            ("workflow_dispatch", "abc"),
            ("push", ""),
            ("push", "0" * 40),
        ]:
            with (
                self.subTest(event=event, base=base),
                patch.dict(
                    os.environ,
                    {"EVENT_NAME": event, "BASE_SHA": base, "HEAD_SHA": "def"},
                ),
            ):
                self.assertIsNone(changed_paths())

    def test_diff_ranges_and_rename_safety(self):
        for event, span in [
            ("pull_request", "abc...def"),
            ("push", "abc..def"),
            ("merge_group", "abc..def"),
        ]:
            with (
                self.subTest(event=event),
                patch.dict(
                    os.environ,
                    {"EVENT_NAME": event, "BASE_SHA": "abc", "HEAD_SHA": "def"},
                ),
                patch(
                    "ci_changes.subprocess.check_output",
                    return_value=b"extractor/old.py\0notes/new.md\0",
                ) as diff,
            ):
                self.assertEqual(changed_paths(), ["extractor/old.py", "notes/new.md"])
                args = diff.call_args.args[0]
                self.assertIn(span, args)
                self.assertIn("--no-renames", args)

    def test_unavailable_history_runs_all(self):
        with (
            patch.dict(
                os.environ, {"EVENT_NAME": "push", "BASE_SHA": "abc", "HEAD_SHA": "def"}
            ),
            patch(
                "ci_changes.subprocess.check_output",
                side_effect=subprocess.CalledProcessError(1, "git"),
            ),
        ):
            self.assertIsNone(changed_paths())


if __name__ == "__main__":
    unittest.main()
