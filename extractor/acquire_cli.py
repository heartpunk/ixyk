# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Artifact-producing boundary preserving independent instruction acquisitions."""

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
from extractor.acquisition_errors import EXPECTED_ACQUISITION
from extractor.evidence_session import (
    add_recording_arguments,
    recording_options,
    recording_session,
)


class _Options(Protocol):
    instruction_hex: str
    model_output: Path
    result_output: Path
    source: int
    recording: str
    evidence_output: Path | None
    commit: str | None
    invocation_id: str | None


class AcquisitionReport(TypedDict):
    schema: str
    status: Literal["pass", "unsupported", "acquisition_error"]
    instruction_hex: str
    error: str | None
    model_route: str | None
    retained_models: list[dict[str, object]]
    findings: list[dict[str, str]]


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
    add_recording_arguments(parser)
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    recording = recording_options(parser, options)
    try:
        instruction = bytes.fromhex(options.instruction_hex)
    except ValueError as error:
        parser.error(str(error))
    if not instruction:
        parser.error("instruction must contain at least one byte")

    status: Literal["pass", "unsupported", "acquisition_error"] = "pass"
    error_text: str | None = None
    retained = {}
    findings = []
    stage = ["acquisition", instruction]
    route = None
    with recording_session(recording) as evidence:

        def on_model(code, model, model_route):
            if model_route == "direct":
                retained[code] = model
            if evidence is not None:
                evidence.model(code, model, model_route, context="acquisition")

        def on_stage(name, code):
            stage[:] = [name, code]

        def on_finding(name, code, error):
            findings.append(
                dict(
                    stage=name,
                    instruction_hex=code.hex(),
                    error_kind=type(error).__name__,
                    message=str(error),
                )
            )
            if evidence is not None:
                evidence.finding(name, code, error, context="acquisition")

        try:
            model = extract(
                load_shellcode(instruction, options.source),
                options.source,
                on_model=on_model,
                on_stage=on_stage,
                on_finding=on_finding,
            )
            route = "generalized"
        except EXPECTED_ACQUISITION as error:
            on_finding(stage[0], stage[1], error)
            status = (
                "unsupported"
                if isinstance(error, (Amd64AdapterError, UnsupportedTheoryError))
                else "acquisition_error"
            )
            error_text = f"{type(error).__name__}: {error}"
            model = retained.get(instruction)
            if model is not None:
                route = "direct"
        model_value = (
            model.to_data()
            if model is not None
            else {
                "schema": "ixyk.unavailable_instruction_model.v1",
                "status": status,
                "error": error_text,
            }
        )

    report: AcquisitionReport = {
        "schema": "ixyk.instruction_acquisition.v1",
        "status": status,
        "instruction_hex": instruction.hex(),
        "error": error_text,
        "model_route": route,
        "retained_models": [
            dict(instruction_hex=code.hex(), model=model.to_data())
            for code, model in retained.items()
        ],
        "findings": findings,
    }
    _write_json(options.model_output, model_value)
    _write_json(options.result_output, report)
