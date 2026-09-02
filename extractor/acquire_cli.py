"""Fail-closed, artifact-producing boundary for one instruction acquisition."""

# Runtime must preload declared libstdc++ before Z3 or Angr imports.
from extractor.runtime import load_shellcode

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
from typing import Literal, Protocol, TypedDict, cast

from extractor.amd64_state import Amd64AdapterError
from extractor.artifact import UnsupportedTheoryError
from extractor.extract_cli import DEFAULT_SOURCE, source_address
from extractor.extractor import extract


class _Options(Protocol):
    instruction_hex: str
    model_output: Path
    result_output: Path
    source: int


class AcquisitionReport(TypedDict):
    schema: str
    status: Literal["pass", "unsupported", "acquisition_error"]
    instruction_hex: str
    error: str | None


def _write_json(path: Path, value: object) -> None:
    _ = path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(arguments: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--instruction-hex", required=True)
    _ = parser.add_argument("--model-output", required=True, type=Path)
    _ = parser.add_argument("--result-output", required=True, type=Path)
    _ = parser.add_argument("--source", default=DEFAULT_SOURCE, type=source_address)
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    try:
        instruction = bytes.fromhex(options.instruction_hex)
    except ValueError as error:
        parser.error(str(error))
    if not instruction:
        parser.error("instruction must contain at least one byte")

    status: Literal["pass", "unsupported", "acquisition_error"] = "pass"
    error_text: str | None = None
    try:
        model = extract(load_shellcode(instruction, options.source), options.source)
        model_value: object = model.to_data()
    except (Amd64AdapterError, UnsupportedTheoryError) as error:
        status, error_text = "unsupported", str(error)
        model_value = {
            "schema": "ixyk.unavailable_instruction_model.v1",
            "status": status,
            "error": error_text,
        }
    except Exception as error:
        status = "acquisition_error"
        error_text = f"{type(error).__name__}: {error}"
        model_value = {
            "schema": "ixyk.unavailable_instruction_model.v1",
            "status": status,
            "error": error_text,
        }

    report: AcquisitionReport = {
        "schema": "ixyk.instruction_acquisition.v1",
        "status": status,
        "instruction_hex": instruction.hex(),
        "error": error_text,
    }
    _write_json(options.model_output, model_value)
    _write_json(options.result_output, report)
