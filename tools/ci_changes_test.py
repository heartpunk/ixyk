"""Regression cases for cheap, conservative CI selection."""

import os
from contextlib import redirect_stdout
import io
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ci_changes import SUITES, affected, changed_paths


class SelectionTest(unittest.TestCase):
    def test_dependency_map(self):
        cases = {
            "LICENSE": set(),
            "CITATION.cff": set(),
            ".github/FUNDING.yml": set(),
            "third_party/arpy/arpy.py": {"lint", "au"},
            "tools/ci_reapi.py": {"lint", "au"},
            ".bazelrc": {"lint", "au"},
            ".bazelversion": {"lint", "au"},
            "tools/native.bzl": {"lint", "au"},
            "lean-toolchain": {"lean", "differential"},
            "lake-manifest.json": {"lean", "differential"},
            "extractor/environment.nix": SUITES,
            ".github/check.lean": SUITES,
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
                self.assertEqual(affected([path.encode().decode()]), expected)

    def test_union_and_empty(self):
        self.assertEqual(SUITES, {"lint", "golden", "lean", "differential", "au"})
        self.assertEqual(
            affected(["artifacts/golden/2_add.model.json", "extractor/artifact.py"]),
            SUITES,
        )
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
                patch("ci_changes.subprocess.check_output") as diff,
            ):
                self.assertIsNone(changed_paths())
                diff.assert_not_called()

    def test_missing_head(self):
        with (
            patch.dict(
                os.environ, {"EVENT_NAME": "push", "BASE_SHA": "abc", "HEAD_SHA": ""}
            ),
            patch("ci_changes.subprocess.check_output") as diff,
        ):
            self.assertIsNone(changed_paths())
            diff.assert_not_called()

    def test_nonzero_sha_containing_zero_and_empty_diff(self):
        with (
            patch.dict(
                os.environ,
                {"EVENT_NAME": "push", "BASE_SHA": "abc0", "HEAD_SHA": "def"},
            ),
            patch("ci_changes.subprocess.check_output", return_value=b"") as diff,
        ):
            self.assertEqual(changed_paths(), [])
            diff.assert_called_once_with(
                ["git", "diff", "--name-only", "--no-renames", "-z", "abc0..def", "--"]
            )

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
                self.assertEqual(
                    args,
                    ["git", "diff", "--name-only", "--no-renames", "-z", span, "--"],
                )

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

    def test_cli_outputs(self):
        for event, data, enabled in [
            (
                "workflow_dispatch",
                b"",
                {"lint", "golden", "lean", "differential", "au"},
            ),
            ("push", b"README.md\0", set()),
            (
                "pull_request",
                b"extractor/typed_z3.py\0",
                {"lint", "au", "differential"},
            ),
        ]:
            with self.subTest(event=event), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                output.write_text("existing=value\n")
                stdout = io.StringIO()
                with (
                    patch.dict(
                        os.environ,
                        {
                            "EVENT_NAME": event,
                            "BASE_SHA": "abc",
                            "HEAD_SHA": "def",
                            "GITHUB_OUTPUT": str(output),
                        },
                    ),
                    patch("subprocess.check_output", return_value=data),
                    redirect_stdout(stdout),
                ):
                    runpy.run_path(
                        str(Path(__file__).with_name("ci_changes.py")),
                        run_name="".join(["__", "main", "__"]),
                    )
                expected = "existing=value\n" + "".join(
                    f"{suite}={str(suite in enabled).lower()}\n"
                    for suite in ["au", "differential", "golden", "lean", "lint"]
                )
                self.assertEqual(output.read_text(), expected)
                self.assertEqual(
                    stdout.getvalue(),
                    "Selected suites: "
                    + (", ".join(sorted(enabled)) or "none (documentation only)")
                    + "\n",
                )

    def test_import_has_no_output_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.dict(
                os.environ,
                {"EVENT_NAME": "workflow_dispatch", "GITHUB_OUTPUT": str(output)},
            ):
                runpy.run_path(
                    str(Path(__file__).with_name("ci_changes.py")),
                    run_name="__ci_filter_import__",
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
