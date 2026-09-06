"""Ensure corrupt or incomplete corpora cannot pass their integrity gate."""

from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import unittest

from ci_golden import verify
from golden import _artifact_contents, _check, _update


class GoldenIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = Path(__file__).resolve().parents[1]
        shutil.copytree(source / "artifacts/golden", self.root / "artifacts/golden")
        shutil.copytree(source / "catalog", self.root / "catalog")

    def test_current_corpus(self):
        self.assertGreater(sum(verify(self.root).values()), 0)

    def test_corruption(self):
        directory = self.root / "artifacts/golden"
        path = directory / "2_add.acquisition.json.zst"
        if not path.exists():
            path = directory / "2_add.acquisition.json"
        path.write_bytes(b"{}")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_missing_entry(self):
        manifest = self.root / "artifacts/golden/MANIFEST.sha256"
        manifest.write_text("\n".join(manifest.read_text().splitlines()[1:]) + "\n")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_extra_artifact(self):
        (self.root / "artifacts/golden/unexpected.json").write_text("{}")
        with self.assertRaises(ValueError):
            verify(self.root)


class GoldenCompressionTest(unittest.TestCase):
    def test_both_json_artifacts_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            original = b'{"schema":"test","payload":[1,2,3]}\n'
            source.write_bytes(original)
            for suffix in ("model.json.zst", "acquisition.json.zst"):
                with self.subTest(suffix=suffix):
                    encoded = _artifact_contents(
                        PurePosixPath("1_mov." + suffix), source
                    )
                    decoded = subprocess.check_output(["zstd", "-dc"], input=encoded)
                    self.assertEqual(decoded, original)
                    self.assertEqual(
                        encoded,
                        _artifact_contents(PurePosixPath("1_mov." + suffix), source),
                    )

    def test_update_retires_only_replaced_plain_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plain = directory / "1_mov.acquisition.json"
            plain.write_bytes(b"old acquisition")
            unrelated = directory / "keep.json"
            unrelated.write_bytes(b"keep")
            contents = {PurePosixPath("1_mov.acquisition.json.zst"): b"compressed"}
            self.assertEqual(_update(directory, contents), 0)
            self.assertFalse(plain.exists())
            self.assertEqual(unrelated.read_bytes(), b"keep")
            self.assertEqual(_check(directory, contents), 0)
            self.assertEqual(_update(directory, contents), 0)

    def test_update_preserves_explicit_plain_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            contents = {
                PurePosixPath("1_mov.acquisition.json"): b"plain",
                PurePosixPath("1_mov.acquisition.json.zst"): b"compressed",
            }
            self.assertEqual(_update(directory, contents), 0)
            self.assertEqual(_check(directory, contents), 0)


if __name__ == "__main__":
    unittest.main()
