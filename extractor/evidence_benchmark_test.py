# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hypothesis import given, settings, strategies as st
import pytest
import zstandard

from extractor import evidence_benchmark as benchmark
from extractor.evidence import EvidenceReader
from extractor.evidence_events import (
    Comparison,
    FuzzInput,
    StateSnapshot,
    evidence_types,
)
from extractor.evidence_reference_json import ReferenceJSONBackend


def arguments(directory, recording="off", samples=100):
    return [
        "--recording",
        recording,
        "--commit",
        "a" * 40,
        "--invocation-id",
        "00000000-0000-0000-0000-000000000001",
        "--output-dir",
        str(directory),
        "--samples",
        str(samples),
    ]


def test_off_never_constructs_recording_and_uses_shared_workload():
    calls = []

    def fuzz(model, code, count, **kwargs):
        calls.append((model, code, count, kwargs))
        return {"executions": count}

    with (
        TemporaryDirectory() as directory,
        patch.object(benchmark, "_fuzz", side_effect=fuzz),
        patch.object(
            benchmark,
            "BackgroundRecorder",
            side_effect=AssertionError("off constructed recorder"),
        ),
        patch.object(
            benchmark,
            "EvidenceHooks",
            side_effect=AssertionError("off constructed hooks"),
        ),
    ):
        result = benchmark.main(arguments(directory))
        assert [call[1] for call in calls] == [
            bytes.fromhex(code) for _, code in benchmark.CASES
        ]
        assert all(
            call[2] == 100
            and call[3]
            == {
                "stage": "discover",
                "vary_inputs": True,
                "continue_on_findings": True,
                "evidence": None,
                "max_executions": 100,
            }
            for call in calls
        )
        assert all(
            case["recording"] is None and case["output_bytes"] == 0
            for case in result["cases"]
        )
        assert list(Path(directory).glob("*.zst")) == []


@given(st.lists(st.binary(min_size=1, max_size=15), min_size=1, max_size=10))
@settings(deadline=None)
def test_reference_cli_compressed_round_trip(inputs):
    def fuzz(model, code, count, **kwargs):
        hooks = kwargs["evidence"]
        for index, instruction in enumerate(inputs):
            before = StateSnapshot((("rip", 4096 + index),), ((8192, index),))
            input_id = hooks.recorder.emit(
                FuzzInput(index, instruction, before, None, "unavailable")
            )
            hooks.recorder.emit(
                Comparison("unusable", None, before, "continued", ()), context=input_id
            )
            hooks.recorder.sample_complete()
        return {"executions": count, "unusable": count}

    with (
        TemporaryDirectory() as directory,
        patch.object(benchmark, "_fuzz", side_effect=fuzz),
    ):
        result = benchmark.main(arguments(directory, "reference-json", len(inputs)))
        for case in result["cases"]:
            encoded = (Path(directory) / f"{case['opcode']}.evidence.zst").read_bytes()
            with zstandard.ZstdDecompressor().stream_reader(
                BytesIO(encoded)
            ) as decompressed:
                reader = EvidenceReader(
                    decompressed, backend=ReferenceJSONBackend(), types=evidence_types()
                )
                records = list(reader)
            assert [record.value.instruction for record in records[::2]] == inputs
            assert all(
                outcome.context == source.id
                for source, outcome in zip(records[::2], records[1::2])
            )
            assert reader.manifest["commit"] == "a" * 40
            assert case["recording"]["records"] == 2 * len(inputs)
            assert case["recording"]["flushes"] == len(inputs)
            assert case["output_bytes"] == len(encoded)


def test_opcode_filter_runs_only_requested_opcode():
    with (
        TemporaryDirectory() as directory,
        patch.object(benchmark, "_fuzz", return_value={"executions": 100}) as fuzz,
    ):
        result = benchmark.main(arguments(directory) + ["--opcode", "ADD"])
    assert [case["opcode"] for case in result["cases"]] == ["ADD"]
    assert fuzz.call_count == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
