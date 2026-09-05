# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Failures survive independent, bounded discovery and processing actions."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hypothesis import strategies as st

from extractor.runtime import load_shellcode
from extractor.extractor import extract
from extractor.fuzz_cli import main as fuzz_main
from extractor.fuzzer import fuzz
from extractor.amd64_state import GPR64, YMM256
from extractor.fuzz_runner import run_bounded

BSR = bytes.fromhex("480fbdc3")
SOURCE = 0x400000


def main() -> None:
    model = extract(load_shellcode(BSR, SOURCE), SOURCE)
    discovery = fuzz(model, BSR, 100, max_executions=101)
    assert discovery["status"] == "mismatch", discovery
    assert discovery["processing"] == "complete", discovery
    assert discovery["executions"] <= 3, discovery
    assert discovery["checkpoint"]["entries"], discovery
    assert "explanation" not in discovery
    saved = json.loads(json.dumps(discovery))
    shrunk = fuzz(model, BSR, 100, stage="shrink", previous=saved, max_executions=30)
    assert shrunk["status"] == "mismatch", shrunk
    assert shrunk["executions"] <= 30, shrunk
    assert shrunk["checkpoint"]["entries"], shrunk
    assert "explanation" not in shrunk
    explained = fuzz(
        model, BSR, 100, stage="explain", previous=shrunk, max_executions=5
    )
    assert explained["status"] == "mismatch", explained
    assert explained["processing"] == "incomplete", explained
    assert explained["reason"] == "execution budget exhausted", explained
    assert explained["executions"] == 5, explained
    assert explained["witness"] == shrunk["witness"]
    single = fuzz(model, BSR, 100, max_executions=1)
    assert single["status"] == "mismatch", single
    assert single["processing"] == "incomplete", single
    assert single["checkpoint"]["entries"], single
    stale = json.loads(json.dumps(saved))
    stale["checkpoint"]["identity"]["hypothesis"] = "wrong-version"
    try:
        fuzz(model, BSR, 100, stage="shrink", previous=stale)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted a stale checkpoint")
    with patch("extractor.fuzzer.CompiledModel.differences", return_value=()):
        missing = fuzz(model, BSR, 100, stage="shrink", previous=saved)
        assert missing["status"] == "mismatch", missing
        assert missing["processing"] == "incomplete", missing
        assert "did not reproduce" in missing["reason"], missing
        assert missing["executions"] <= 3, missing

    # A nonminimal failure proves that the follow-up really shrinks, rather
    # than merely replaying a primary-corpus entry and returning early.
    registers = st.tuples(
        *(
            st.integers(0, 255)
            if name == "rax"
            else st.just(4096 if name == "rsp" else 0)
            for name in GPR64 + YMM256
        )
    )
    with (
        patch("extractor.fuzzer._REGISTERS", registers),
        patch(
            "extractor.fuzzer.emulate", side_effect=lambda instruction, before: before
        ),
        patch(
            "extractor.fuzzer.CompiledModel.differences",
            side_effect=lambda before, after: (
                ("synthetic",) if before.scalars["rax"] >= 128 else ()
            ),
        ),
    ):
        large = fuzz(model, BSR, 100)
        small = fuzz(
            model, BSR, 100, stage="shrink", previous=large, max_executions=500
        )
        assert large["witness"]["rax"] > 128, large
        assert small["witness"]["rax"] == 128, small
        assert small["processing"] == "complete", small
        explanation = fuzz(
            model, BSR, 100, stage="explain", previous=small, max_executions=500
        )
        assert explanation["processing"] == "complete", explanation
        assert explanation["explanation"], explanation

    timed = run_bounded(
        model.to_json(),
        BSR,
        0.001,
        examples=100,
        stage="shrink",
        previous=saved,
        max_executions=30,
    )
    assert timed["status"] == "mismatch", timed
    assert timed["processing"] == "incomplete", timed
    assert timed["reason"] == "time budget exhausted", timed
    assert timed["witness"] == saved["witness"], timed
    assert timed["elapsed_seconds"] < 5, timed
    with TemporaryDirectory() as temporary:
        directory = Path(temporary)
        acquisition, model_path = (
            directory / "acquisition.json",
            directory / "model.json",
        )
        prior, output = directory / "prior.json", directory / "output.json"
        acquisition.write_text(
            json.dumps(
                {
                    "schema": "ixyk.instruction_acquisition.v1",
                    "status": "pass",
                    "instruction_hex": BSR.hex(),
                }
            )
        )
        model_path.write_text(model.to_json())
        prior.write_text(json.dumps(saved))
        arguments = [
            "--acquisition",
            str(acquisition),
            "--model",
            str(model_path),
            "--instruction-hex",
            BSR.hex(),
            "--examples",
            "100",
            "--output",
            str(output),
            "--stage",
            "shrink",
            "--previous",
            str(prior),
            "--max-executions",
            "10",
        ]
        fuzz_main(arguments)
        result = json.loads(output.read_text())
        assert result["status"] == "mismatch", result
        assert result["executions"] <= 10, result
        prior.write_text(json.dumps(dict(saved, status="pass")))
        model_path.write_text("not a model")
        fuzz_main(arguments)
        result = json.loads(output.read_text())
        assert result["status"] == "not_applicable", result
        assert result["executions"] == 0, result


if __name__ == "__main__":
    main()
