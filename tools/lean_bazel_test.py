"""Tests for source isolation and evidence parsing in the Lean reproduction gate."""

import json
from pathlib import Path
import tempfile
import unittest

from lean_reproduce import artifact_hashes, module_actions, remove_tree, snapshot
from lean_runfiles import resolve


class ReproductionTest(unittest.TestCase):
    def test_snapshot_excludes_local_configuration_and_build_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            for name in (
                "Ixyk.lean",
                "third_party/rules/tool.bzl",
                ".bazelrc",
                ".bazelrc.local",
                ".lake/build/stale.olean",
                ".jj/repo/private",
                "bazel-out/output",
            ):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            inventory = snapshot(source, root / "copy")
            self.assertEqual(
                set(inventory), {"Ixyk.lean", "third_party/rules/tool.bzl", ".bazelrc"}
            )

    def test_snapshot_rejects_escaping_source_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            secret = root / "outside"
            secret.write_text("not part of the artifact")
            (source / "input").symlink_to(secret)
            with self.assertRaisesRegex(ValueError, "escapes the archive"):
                snapshot(source, root / "copy")

    def test_execution_log_selects_consumer_elaboration_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "execution.json"
            records = [
                {
                    "mnemonic": "LeanCompile",
                    "targetLabel": "//:module__ixyk__Ixyk",
                    "cacheHit": True,
                },
                {
                    "mnemonic": "LeanCompile",
                    "targetLabel": "@@lean_bazel+//tools:projection_lake_model",
                    "cacheHit": False,
                },
                {
                    "mnemonic": "LeanNativeCompile",
                    "targetLabel": "//:module__ixyk__Ixyk",
                    "cacheHit": False,
                },
            ]
            path.write_text(
                "\n".join(json.dumps(record, indent=2) for record in records)
            )
            self.assertEqual(module_actions(path), records[:1])

    def test_artifact_hashes_exclude_bazel_runfiles_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            names = [
                "olean-root/Ixyk.olean",
                "bin/ixyk-golden-check",
                "bin/ixyk-differential-eval",
            ]
            for name in [
                *names,
                "bin/ixyk-golden-check.repo_mapping",
                "bin/ixyk-differential-eval.runfiles_manifest",
            ]:
                path = output / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            self.assertEqual(set(artifact_hashes(output)), set(names))

    def test_remove_readonly_outputs_preserves_external_symlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "immutable"
            outside.mkdir()
            outside.chmod(0o755)
            output = root / "output"
            output.mkdir()
            (output / "external").symlink_to(outside, target_is_directory=True)
            readonly = output / "readonly"
            readonly.mkdir()
            (readonly / "artifact").write_text("output")
            readonly.chmod(0o555)
            remove_tree(output)
            self.assertFalse(output.exists())
            self.assertEqual(outside.stat().st_mode & 0o777, 0o755)

    def test_executable_resolution_preserves_launcher_adjacency(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trampoline = root / "trampoline"
            trampoline.write_text("shared runtime launcher")
            launcher = root / "binary"
            launcher.symlink_to(trampoline)
            self.assertEqual(resolve(launcher), launcher)
            self.assertNotEqual(resolve(launcher), trampoline)


if __name__ == "__main__":
    unittest.main()
