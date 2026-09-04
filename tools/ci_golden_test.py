"""Ensure corrupt or incomplete corpora cannot pass their integrity gate."""

from pathlib import Path
import shutil
import tempfile
import unittest

from ci_golden import verify


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
        (self.root / "artifacts/golden/2_add.acquisition.json").write_text("{}")
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


if __name__ == "__main__":
    unittest.main()
