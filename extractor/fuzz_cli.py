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

from extractor.artifact import InstructionModel
from extractor.fuzzer import fuzz


class _Options(Protocol):
    acquisition: Path
    examples: int
    instruction_hex: str
    model: Path
    output: Path


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
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    try:
        instruction = bytes.fromhex(options.instruction_hex)
    except ValueError as error:
        parser.error(str(error))
    if not instruction:
        parser.error("instruction must contain at least one byte")
    raw_acquisition = cast(
        object, json.loads(options.acquisition.read_text(encoding="utf-8"))
    )
    if not isinstance(raw_acquisition, dict):
        raise ValueError("acquisition result is not an object")
    acquisition = cast(dict[str, object], raw_acquisition)
    if acquisition.get("schema") != "ixyk.instruction_acquisition.v1":
        raise ValueError("acquisition result has the wrong schema")
    if acquisition.get("instruction_hex") != instruction.hex():
        raise ValueError("acquisition result belongs to a different instruction")
    status = acquisition.get("status")
    if status == "pass":
        model = InstructionModel.from_json(options.model.read_text(encoding="utf-8"))
        report: object = fuzz(model, instruction, options.examples)
    elif status in {"unsupported", "acquisition_error"}:
        report = {
            "schema": "ixyk.differential_fuzz.v1",
            "status": status,
            "instruction_hex": instruction.hex(),
            "examples_requested": options.examples,
            "executions": 0,
            "error": acquisition.get("error"),
        }
    else:
        raise ValueError(f"acquisition result has invalid status {status!r}")
    _ = options.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
