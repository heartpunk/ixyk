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

from ci_changes import (
    ALL_SUITES, BLANK_VM_INPUTS, CACHE_INPUTS, DOCKER_INPUTS, NEWCOMER_INPUTS, SUITES, affected, changed_paths,
)


class SelectionTest(unittest.TestCase):
    def test_dependency_map(self):
        cases = {
            "LICENSE": set(),
            "CITATION.cff": set(),
            ".github/FUNDING.yml": set(),
            "third_party/arpy/arpy.py": {"lint", "au"},
            "tools/ci_reapi.py": {"lint", "au"},
            "tools/reapi.py": {"lint", "au"},
            "tools/reapi_test.py": {"lint", "au"},
            ".bazelrc": {"lint", "au", "lean", "differential"},
            ".bazelversion": {"lint", "au", "lean", "differential"},
            "tools/native.bzl": {"lint", "au", "lean", "differential"},
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
            "MODULE.bazel.lock": {"lint", "au", "lean", "differential"},
            "third_party/lean_bazel/tools/lean_module.bzl": {"lint", "lean", "differential"},
            "lean/x86_64-linux/projection-lock.json": {"lint", "lean", "differential"},
            "flake.lock": SUITES,
            "flake.nix": SUITES,
            ".github/actions/changes/action.yml": SUITES,
            "tools/ci_changes.py": SUITES,
            "unknown/new-input.json": SUITES,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(
                    affected([path.encode().decode()]),
                    expected | ({"newcomer"} if path in NEWCOMER_INPUTS else set())
                    | ({"blank_vm"} if path in BLANK_VM_INPUTS else set())
                    | ({"docker"} if path in DOCKER_INPUTS else set())
                    | ({"cache"} if path in CACHE_INPUTS else set()),
                )

    def test_cache_selection(self):
        for path in ("nix/dev-environment.nix", "nix/lean.nix", "nix/reapi.nix", "tools/xed_enc2.nix",
                     ".github/workflows/cachix.yml", "tools/ci_cachix_restore.py"):
            self.assertIn("cache", affected([path]))
        for path in ("README.md", "extractor/xed.py", "compose.reapi.yaml",
                     "nix/docker-image.nix", "tools/ci_blank_vm.sh", "unknown/file"):
            self.assertNotIn("cache", affected([path]))

    def test_newcomer_exact_inputs(self):
        inputs = {
            "flake.nix", "flake.lock", "nix/dev-environment.nix", "nix/lean.nix",
            "tools/xed_enc2.nix", "tools/xed_enc2_dispatch.py",
            "tools/dev_check.py", "tools/dev_smoke.py", ".bazelversion",
            "lean-toolchain", ".github/workflows/dev-environment.yml",
            ".github/actions/changes/action.yml", "tools/ci_changes.py",
        }
        self.assertEqual(NEWCOMER_INPUTS, inputs)
        for path in inputs:
            with self.subTest(path=path):
                self.assertIn("newcomer", affected([path]))

    def test_newcomer_skips_unrelated_and_unknown_paths(self):
        for path in (
            "extractor/artifact.py", "antiunification/algebra.py",
            "Ixyk/QfAbv/Semantics.lean", "catalog/x86_64_probes.json",
            "artifacts/golden/2_add.model.json", "lakefile.lean",
            "tools/ci_lean.py", "tools/lean_fuzz_env.nix",
            "tools/ci_changes_test.py", ".github/workflows/ci.yml",
            ".github/workflows/attic-publish.yml", "MODULE.bazel",
            "MODULE.bazel.lock", ".bazelrc", "tools/nix_python.bzl",
            "README.md", ".envrc", "unknown/new-input.json",
        ):
            with self.subTest(path=path):
                self.assertNotIn("newcomer", affected([path]))
        self.assertIn("newcomer", affected(["README.md", "flake.lock"]))

    def test_blank_vm_exact_inputs(self):
        self.assertEqual(BLANK_VM_INPUTS, NEWCOMER_INPUTS | {
            ".bazelrc", "tools/reapi_platform.bzl",
            "nix/reapi.nix", "tools/reapi.py", "tools/reapi_smoke.py",
            "tools/ci_blank_vm.sh", "tools/ci_blank_guest.sh",
        })
        for path in BLANK_VM_INPUTS:
            self.assertIn("blank_vm", affected([path]))
        for path in (
            "README.md", "unknown/file", "antiunification/algebra.py",
            "catalog/x86_64_probes.json", "MODULE.bazel",
            "tools/reapi_test.py", "tools/ci_changes_test.py",
        ):
            self.assertNotIn("blank_vm", affected([path]))

    def test_docker_inputs(self):
        for path in DOCKER_INPUTS:
            self.assertIn("docker", affected([path]))
        for path in ("README.md", "unknown/file", "tools/ci_blank_vm.sh",
                     "antiunification/algebra.py", "tools/reapi_test.py"):
            self.assertNotIn("docker", affected([path]))
        for path in ("nix/docker-image.nix", "compose.yaml", "tools/ci_docker.sh", "tools/docker.apparmor",
                     ".github/workflows/docker.yml"):
            self.assertIn("docker", affected([path]))
            self.assertNotIn("newcomer", affected([path]))
            self.assertNotIn("blank_vm", affected([path]))

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
                ALL_SUITES,
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
                    for suite in sorted(ALL_SUITES)
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
