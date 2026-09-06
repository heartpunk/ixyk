# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from hypothesis import given, settings, strategies as st
import pytest
import zstandard

from extractor import acquire_cli, extractor as extraction
from extractor.artifact import (
    InstructionModel,
    Declaration,
    Assignment,
    StepSummary,
    Target,
    TermSort,
    TypedExpr as E,
)
from extractor.evidence import EvidenceReader
from extractor.evidence_events import Finding, evidence_types
from extractor.evidence_reference_json import ReferenceJSONBackend
from extractor.evidence_session import recording_session
from extractor.operand_slots import OperandDecodeError


def model_at(source):
    word = TermSort.bv(64)
    pc = E.bv_lit(64, source)
    return InstructionModel(
        source,
        (Declaration("rip", word),),
        (
            StepSummary(
                E.bool_lit(True),
                (Assignment("rip", pc),),
                Target("address", source),
                pc,
            ),
        ),
    )


def read_records(path):
    with (
        path.open("rb") as raw,
        zstandard.ZstdDecompressor().stream_reader(raw) as stream,
    ):
        reader = EvidenceReader(
            stream, backend=ReferenceJSONBackend(), types=evidence_types()
        )
        return reader.manifest, list(reader)


@given(st.integers(0, 2**64 - 1), st.booleans())
@settings(deadline=None)
def test_acquire_cli_retains_model_when_generalization_fails(source, recording):
    model = model_at(source)

    def acquire(project, address, *, on_model, on_stage, on_finding):
        on_model(b"\x90", model, "direct")
        on_stage("generalization", b"\x90")
        raise OperandDecodeError("forced AU failure")

    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        args = [
            "--instruction-hex",
            "90",
            "--model-output",
            str(root / "model.json"),
            "--result-output",
            str(root / "result.json"),
        ]
        if recording:
            args += [
                "--recording",
                "reference-json",
                "--evidence-output",
                str(root / "evidence.zst"),
                "--commit",
                "a" * 40,
                "--invocation-id",
                "test-acquisition",
            ]
        with (
            patch.object(acquire_cli, "extract", side_effect=acquire),
            patch.object(acquire_cli, "load_shellcode"),
        ):
            acquire_cli.main(args)
        assert InstructionModel.from_json((root / "model.json").read_text()) == model
        report = json.loads((root / "result.json").read_text())
        assert report["model_route"] == "direct"
        assert report["retained_models"] == [
            {"instruction_hex": "90", "model": model.to_data()}
        ]
        assert report["findings"][0]["stage"] == "generalization"
        if recording:
            manifest, records = read_records(root / "evidence.zst")
            assert manifest["commit"] == "a" * 40
            assert manifest["invocation_id"] == "test-acquisition"
            assert model in [record.value for record in records]
            assert any(isinstance(record.value, Finding) for record in records)
        else:
            assert not (root / "evidence.zst").exists()


@given(st.lists(st.booleans(), min_size=2, max_size=12))
@settings(deadline=None)
def test_unsupported_candidate_preserves_successful_siblings(supported):
    # Force at least one successful and one unsupported encoding in every case.
    supported = [True, False, *supported]
    codes = [bytes([i]) for i in range(len(supported))]
    retained, findings, attempts = [], [], []
    model = model_at(4096)
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda *a, **k: SimpleNamespace(bytes=codes[0]))
    )

    def concrete(code, source):
        attempts.append(code)
        if not supported[code[0]]:
            raise OperandDecodeError("unsupported encoding")
        return model

    with (
        patch.object(extraction, "expect_project", return_value=project),
        patch(
            "extractor.runtime.load_shellcode", side_effect=lambda code, source: code
        ),
        patch("extractor.au_inputs.instruction_inputs", return_value=codes),
        patch.object(extraction, "_extract_concrete", side_effect=concrete),
    ):
        with pytest.raises(OperandDecodeError, match="incomplete"):
            extraction.extract(
                project,
                4096,
                on_model=lambda code, model, route: retained.append(code),
                on_finding=lambda stage, code, error: findings.append(code),
            )
    assert attempts == codes
    assert retained == [code for code, ok in zip(codes, supported) if ok]
    assert findings == [code for code, ok in zip(codes, supported) if not ok]


@given(st.lists(st.text(max_size=100), min_size=1, max_size=20))
@settings(deadline=None)
def test_interruption_drains_evidence_and_replay_preserves_ids(messages):
    with TemporaryDirectory() as temporary:
        path = Path(temporary) / "evidence.zst"
        options = dict(
            path=str(path), commit="a" * 40, invocation_id="test-interruption"
        )
        with pytest.raises(KeyboardInterrupt):
            with recording_session(options) as hooks:
                for message in messages:
                    hooks.finding("test", b"\x90", OperandDecodeError(message))
                raise KeyboardInterrupt()
        _, records = read_records(path)
        _, replay = read_records(path)
        assert [record.value.message for record in records] == messages
        assert [record.id for record in records] == [record.id for record in replay]
        assert len({record.id for record in records + replay}) == len(messages)


def test_unexpected_acquisition_exception_propagates():
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        with (
            patch.object(
                acquire_cli, "extract", side_effect=RuntimeError("unexpected")
            ),
            patch.object(acquire_cli, "load_shellcode"),
        ):
            with pytest.raises(RuntimeError, match="unexpected"):
                acquire_cli.main(
                    [
                        "--instruction-hex",
                        "90",
                        "--model-output",
                        str(root / "model.json"),
                        "--result-output",
                        str(root / "result.json"),
                    ]
                )
        assert not (root / "model.json").exists()


@given(st.integers(1, 3))
@settings(max_examples=3, deadline=None)
def test_fuzz_cli_records_subprocess_comparisons(samples):
    from extractor.fuzz_cli import main as fuzz_main
    from extractor.runtime import load_shellcode
    from extractor.evidence_events import Comparison, FuzzInput

    model = extraction.extract(load_shellcode(bytes.fromhex("4801d8"), 4096), 4096)
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "model.json").write_text(model.to_json())
        (root / "acquisition.json").write_text(
            json.dumps(
                {
                    "schema": "ixyk.instruction_acquisition.v1",
                    "instruction_hex": "4801d8",
                    "status": "pass",
                }
            )
        )
        fuzz_main(
            [
                "--acquisition",
                str(root / "acquisition.json"),
                "--model",
                str(root / "model.json"),
                "--instruction-hex",
                "4801d8",
                "--examples",
                str(samples),
                "--max-executions",
                str(samples),
                "--fixed-inputs",
                "--output",
                str(root / "fuzz.json"),
                "--recording",
                "reference-json",
                "--evidence-output",
                str(root / "evidence.zst"),
                "--commit",
                "a" * 40,
                "--invocation-id",
                "cli-test",
            ]
        )
        report = json.loads((root / "fuzz.json").read_text())
        _, records = read_records(root / "evidence.zst")
        inputs = {
            record.id: record.value
            for record in records
            if isinstance(record.value, FuzzInput)
        }
        comparisons = [
            record for record in records if isinstance(record.value, Comparison)
        ]
        assert len(inputs) == len(comparisons) == report["executions"] == samples
        assert all(record.context in inputs for record in comparisons)
        assert all(record.value.model_after is not None for record in comparisons)
        assert (
            sum(record.value.outcome == "agreement" for record in comparisons)
            == report["agreements"]
        )


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("fixed_inputs", [False, True])
def test_fuzz_cli_consumes_the_frozen_acquisition(tmp_path, fallback, fixed_inputs):
    from antiunification.algebra import AlgebraError
    from extractor import fuzz_cli

    code = "4801d8"

    def acquire(project, source, **kwargs):
        if fallback:
            with patch(
                "antiunification.many.antiunify_many",
                side_effect=AlgebraError("forced AU failure"),
            ):
                return extraction.extract(project, source, **kwargs)
        return extraction.extract(project, source, **kwargs)

    model_path, acquisition_path, output_path = [
        tmp_path / name for name in ("model.json", "acquisition.json", "fuzz.json")
    ]
    with patch.object(acquire_cli, "extract", acquire):
        acquire_cli.main(
            [
                "--instruction-hex",
                code,
                "--model-output",
                str(model_path),
                "--result-output",
                str(acquisition_path),
            ]
        )
    acquisition = json.loads(acquisition_path.read_text())
    assert acquisition["model_route"] == ("direct" if fallback else "generalized")
    args = [
        "--instruction-hex",
        code,
        "--model",
        str(model_path),
        "--acquisition",
        str(acquisition_path),
        "--examples",
        "17",
        "--seconds",
        "60",
        "--output",
        str(output_path),
    ]
    if fixed_inputs:
        args.append("--fixed-inputs")
    fuzz_cli.main(args)
    report = json.loads(output_path.read_text())
    assert report["executions"] == 17, report
    assert len(report["prepared_models"]) == (
        len(acquisition["retained_models"]) if fallback else 1
    )
    assert report["fallback_allocations"] == report["planned_fallback_allocations"]
    assert report["acquisition_findings"] == len(acquisition["findings"])
    if fallback:
        assert set(report["fallback_allocations"]) == {
            item["instruction_hex"] for item in acquisition["retained_models"]
        }
    else:
        assert report["prepared_models"][0]["instruction_hex"] == code


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
