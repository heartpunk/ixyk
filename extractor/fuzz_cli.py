# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""File-producing differential-fuzz command line boundary."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
from typing import Protocol, cast

from extractor.z3_runtime import LIBSTDCXX
from extractor.fuzz_runner import run_bounded
from extractor.evidence_session import add_recording_arguments, recording_options


class _Options(Protocol):
    acquisition: Path
    examples: int
    instruction_hex: str
    model: Path
    output: Path
    stage: str
    previous: Path | None
    max_executions: int | None
    seconds: int
    fixed_inputs: bool
    recording: str
    evidence_output: Path | None
    commit: str | None
    invocation_id: str | None


def _positive(value: str) -> int:
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def main(arguments: Sequence[str] | None = None) -> None:
    _ = LIBSTDCXX
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--acquisition", required=True, type=Path)
    _ = parser.add_argument("--model", required=True, type=Path)
    _ = parser.add_argument("--instruction-hex", required=True)
    _ = parser.add_argument("--examples", required=True, type=_positive)
    _ = parser.add_argument("--output", required=True, type=Path)
    _ = parser.add_argument(
        "--stage", choices=("discover", "shrink", "explain"), default="discover"
    )
    _ = parser.add_argument("--previous", type=Path)
    _ = parser.add_argument("--max-executions", type=_positive)
    _ = parser.add_argument("--seconds", type=_positive, default=60)
    _ = parser.add_argument("--fixed-inputs", action="store_true")
    add_recording_arguments(parser)
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    recording = recording_options(parser, options)
    try:
        instruction = bytes.fromhex(options.instruction_hex)
    except ValueError as error:
        parser.error(str(error))
    if not instruction:
        parser.error("instruction must contain at least one byte")
    acquisition = json.loads(options.acquisition.read_text(encoding="utf-8"))
    if acquisition.get("schema") != "ixyk.instruction_acquisition.v1":
        raise ValueError("acquisition result has the wrong schema")
    if acquisition.get("instruction_hex") != instruction.hex():
        raise ValueError("acquisition result belongs to a different instruction")
    previous = None
    if options.previous:
        previous = json.loads(options.previous.read_text(encoding="utf-8"))
        if previous.get("schema") != "ixyk.differential_fuzz.v1":
            raise ValueError("previous report has the wrong schema")
        if previous.get("instruction_hex") != instruction.hex():
            raise ValueError("previous report belongs to a different instruction")
    if (options.stage == "discover") != (previous is None):
        parser.error("shrink/explain require --previous; discover does not accept it")
    if recording is not None and options.stage != "discover":
        parser.error("recording is currently supported for discover")
    status = acquisition.get("status")
    if status not in {"pass", "unsupported", "acquisition_error"}:
        raise ValueError(f"acquisition result has invalid status {status!r}")
    if (
        status == "pass"
        or acquisition.get("model_route") == "direct"
        or not options.fixed_inputs
    ):
        if previous is not None and previous.get("status") != "mismatch":
            report = {
                "schema": "ixyk.differential_fuzz.v1",
                "instruction_hex": instruction.hex(),
                "stage": options.stage,
                "status": "not_applicable",
                "processing": "not_applicable",
                "upstream_status": previous.get("status"),
                "executions": 0,
            }
        elif previous is not None and not previous.get("checkpoint", {}).get("entries"):
            report = dict(
                previous,
                stage=options.stage,
                processing="incomplete",
                executions=0,
                reason="upstream finding has no resumable checkpoint; witness retained",
            )
        else:
            executions = options.max_executions or (
                options.examples + 1 if options.stage == "discover" else 500
            )
            report = run_bounded(
                options.model.read_text(encoding="utf-8"),
                instruction,
                options.seconds,
                examples=options.examples,
                stage=options.stage,
                vary_inputs=not options.fixed_inputs,
                continue_on_findings=options.stage == "discover",
                recording=recording,
                previous=previous,
                max_executions=executions,
            )
    elif status in {"unsupported", "acquisition_error"}:
        report = {
            "schema": "ixyk.differential_fuzz.v1",
            "status": status,
            "instruction_hex": instruction.hex(),
            "examples_requested": options.examples,
            "executions": 0,
            "stage": options.stage,
            "error": acquisition.get("error"),
        }
    else:
        raise ValueError(f"acquisition result has invalid status {status!r}")
    _ = options.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
