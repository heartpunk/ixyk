"""Ensure corrupt or incomplete corpora cannot pass their integrity gate."""

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
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
        self.directory = self.root / "artifacts/golden"
        self.directory.mkdir(parents=True)
        (self.root / "catalog").mkdir()
        probes = [
            {"rank": 1, "name": "NOP", "bytes": "90"},
            {"rank": 2, "name": "MULSD", "bytes": "f20f59c1"},
            {"rank": 3, "name": "CMPXCHG", "bytes": "480fb1d8"},
        ]
        (self.root / "catalog/x86_64_probes.json").write_text(
            json.dumps({"probes": probes})
        )
        # Tiny synthetic protocol fixtures, independent of the archived corpus.
        pc = {"op": "bv_lit", "sort": {"kind": "bv", "width": 64}, "value": 4097}
        model = {
            "schema": "ixyk.qf_abv.instruction.v1",
            "source": 4096,
            "declarations": [{"name": "rip", "sort": {"kind": "bv", "width": 64}}],
            "steps": [{
                "guard": {"op": "bool_lit", "sort": {"kind": "bool"}, "value": True},
                "simultaneous_update": [{"name": "rip", "value": pc}],
                "target": {"kind": "address", "value": 4097},
                "mirrored_pc": pc,
            }],
        }
        statuses = ("pass", "unsupported", "acquisition_error")
        self.acquisitions = {}
        self.models = {}
        for probe, status in zip(probes, statuses):
            stem = f"{probe['rank']}_{probe['name'].lower()}"
            acquisition = {
                "schema": "ixyk.instruction_acquisition.v1",
                "instruction_hex": probe["bytes"],
                "status": status,
                "error": None if status == "pass" else "synthetic failure",
            }
            if status == "unsupported":
                artifact = {
                    "schema": "ixyk.unavailable_instruction_model.v1",
                    "status": status,
                    "error": acquisition["error"],
                }
            else:
                artifact = copy.deepcopy(model)
            if status == "acquisition_error":
                acquisition["model_route"] = "direct"
                acquisition["retained_models"] = [{
                    "instruction_hex": probe["bytes"],
                    "model": copy.deepcopy(artifact),
                }]
            self.acquisitions[stem] = acquisition
            self.models[stem] = artifact
        self.acquisition_suffix = "acquisition.json.zst"
        self.write_corpus()

    def write_corpus(self):
        for stem in self.acquisitions:
            for suffix, data in (
                (self.acquisition_suffix, self.acquisitions[stem]),
                ("model.json.zst", self.models[stem]),
            ):
                contents = json.dumps(data, sort_keys=True).encode()
                if suffix.endswith(".zst"):
                    contents = subprocess.check_output(
                        ["zstd", "-q", "-c"], input=contents
                    )
                (self.directory / f"{stem}.{suffix}").write_bytes(contents)
        entries = [
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(self.directory.iterdir())
            if path.name != "MANIFEST.sha256"
        ]
        (self.directory / "MANIFEST.sha256").write_text("".join(entries))

    def test_synthetic_corpus(self):
        self.assertEqual(
            verify(self.root), {"pass": 1, "unsupported": 1, "acquisition_error": 1}
        )

    def test_plain_acquisition_compatibility(self):
        for stem in self.acquisitions:
            (self.directory / f"{stem}.{self.acquisition_suffix}").unlink()
        self.acquisition_suffix = "acquisition.json"
        self.write_corpus()
        self.test_synthetic_corpus()

    def test_direct_model_requires_retained_copy(self):
        self.acquisitions["3_cmpxchg"]["retained_models"] = []
        self.write_corpus()
        with self.assertRaisesRegex(ValueError, "direct model is not retained"):
            verify(self.root)

    def test_direct_model_requires_exact_match(self):
        retained = self.acquisitions["3_cmpxchg"]["retained_models"][0]
        retained["model"]["source"] = 8192
        self.write_corpus()
        with self.assertRaisesRegex(ValueError, "direct model is not retained"):
            verify(self.root)

    def test_direct_model_requires_same_instruction(self):
        self.acquisitions["3_cmpxchg"]["retained_models"][0]["instruction_hex"] = "90"
        self.write_corpus()
        with self.assertRaisesRegex(ValueError, "direct model is not retained"):
            verify(self.root)

    def test_unavailable_model_preserves_error(self):
        self.models["2_mulsd"]["error"] = "different failure"
        self.write_corpus()
        with self.assertRaisesRegex(ValueError, "unavailable model disagrees"):
            verify(self.root)

    def test_corruption(self):
        (self.directory / "1_nop.acquisition.json.zst").write_bytes(b"{}")
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
