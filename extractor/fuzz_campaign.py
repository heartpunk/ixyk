# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cumulative outcomes and shared fallback scheduling for differential fuzzing."""

import hashlib
from dataclasses import dataclass
from time import perf_counter_ns
from typing import Literal

from extractor.acquisition_errors import EXPECTED_ACQUISITION
from extractor.evidence_events import Comparison, FuzzInput, StateSnapshot
from extractor.extractor import extract
from extractor.fuzzer import ComparisonUnavailable, CompiledModel, InputLayout, emulate
from extractor.runtime import load_shellcode
from extractor.unicorn_boundary import is_cpu_exception, is_emulator_error


@dataclass(frozen=True)
class PreparedModel:
    code: bytes
    source: int
    compiled: CompiledModel
    layout: InputLayout
    route: Literal["generalized", "fallback"]
    model_id: str | None


class Campaign:
    def __init__(self, instruction, evidence=None, *, fixed_model=None):
        self.instruction, self.evidence = instruction, evidence
        self.fixed_model = fixed_model
        self.models: tuple[PreparedModel, ...] = ()
        self.prepared = False
        self.allocations = {}
        self.model_id = None
        self.route: Literal["generalized", "fallback", "unavailable"] = "unavailable"
        self.agreements = self.disagreements = self.unusable = 0
        self.acquisition_findings = self.generation_findings = 0
        self.first_disagreement = None
        self.digest = hashlib.sha256()

    def form_unavailable(self, form, error):
        self.generation_findings += 1
        if self.evidence is not None:
            self.evidence.finding(f"generation:form:{form}", self.instruction, error)

    def prepare(self, *, source=0x400000, acquisition=None):
        if self.prepared:
            raise RuntimeError("campaign models are already frozen")
        retained = []
        stage = ["acquisition", self.instruction]
        identifiers = {}

        def on_model(code, model, route):
            if route == "direct":
                retained.append((code, model))
            if self.evidence is not None:
                identifiers[code, route] = self.evidence.model(
                    code, model, route, context="preparation"
                )

        def on_stage(name, code):
            stage[:] = [name, code]

        def on_finding(name, code, error):
            self.acquisition_findings += 1
            if self.evidence is not None:
                self.evidence.finding(name, code, error, context="preparation")

        model = self.fixed_model
        if acquisition is not None:
            from extractor.artifact import InstructionModel

            if acquisition.get("schema") != "ixyk.instruction_acquisition.v1":
                raise ValueError("acquisition result has the wrong schema")
            if acquisition.get("instruction_hex") != self.instruction.hex():
                raise ValueError(
                    "acquisition result belongs to a different instruction"
                )
            for finding in acquisition.get("findings", ()):
                self.acquisition_findings += 1
                if self.evidence is not None:
                    from extractor.evidence_events import Finding

                    self.evidence.recorder.emit(
                        Finding(
                            finding["stage"],
                            bytes.fromhex(finding["instruction_hex"]),
                            finding["error_kind"],
                            finding["message"],
                        ),
                        context="preparation",
                    )
            if (
                acquisition.get(
                    "model_route",
                    "generalized" if acquisition.get("status") == "pass" else None,
                )
                != "generalized"
            ):
                model = None
                retained = [
                    (
                        bytes.fromhex(item["instruction_hex"]),
                        InstructionModel.from_data(item["model"]),
                    )
                    for item in acquisition.get("retained_models", ())
                ]
                if not retained and self.fixed_model is not None:
                    retained = [(self.instruction, self.fixed_model)]
        elif model is None:
            try:
                model = extract(
                    load_shellcode(self.instruction, source),
                    source,
                    on_model=on_model,
                    on_stage=on_stage,
                    on_finding=on_finding,
                )
            except EXPECTED_ACQUISITION as error:
                on_finding(stage[0], stage[1], error)

        entries = [(self.instruction, model)] if model is not None else retained
        route = "generalized" if model is not None else "fallback"
        prepared = []

        for code, artifact in entries:
            compiled = CompiledModel(artifact)
            layout = InputLayout.prepare(code)
            evidence_route = "generalized" if model is not None else "direct"
            identifier = identifiers.get((code, evidence_route))
            if self.evidence is not None and identifier is None:
                identifier = self.evidence.model(
                    code, artifact, evidence_route, context="preparation"
                )
            prepared.append(
                PreparedModel(
                    code, artifact.source, compiled, layout, route, identifier
                )
            )
        self.models = tuple(prepared)
        self.prepared = True

    def select(self, sample):
        if not self.prepared:
            raise RuntimeError("campaign must be prepared before sampling")
        if not self.models:
            raise RuntimeError("campaign has no executable models")
        selected = self.models[(sample - 1) % len(self.models)]
        self.model_id, self.route = selected.model_id, selected.route
        if selected.route == "fallback":
            key = selected.code.hex()
            self.allocations[key] = self.allocations.get(key, 0) + 1
        return selected

    def _fingerprint(self, code, before):
        # Same audit in all configurations; catches any timing-dependent input drift.
        self.digest.update(len(code).to_bytes(2, "big") + code)
        for name, value in sorted(before.scalars.items()):
            self.digest.update(name.encode() + b"\0" + value.to_bytes(32, "big"))
        self.digest.update(len(before.memory).to_bytes(8, "big"))
        for address, byte in sorted(before.memory.items()):
            self.digest.update(address.to_bytes(8, "big") + bytes((byte,)))

    def compare(self, current, code, before, sample):
        self._fingerprint(code, before)
        context, prediction, after = None, [], None
        if self.evidence is not None:
            recorder = self.evidence.recorder
            context = recorder.capture(
                lambda: FuzzInput(
                    sample,
                    code,
                    StateSnapshot.capture(before),
                    self.model_id,
                    self.route,
                )
            )

        def capture_prediction(factory):
            started = perf_counter_ns()
            prediction.append(factory())
            recorder.metrics.capture_ns += perf_counter_ns() - started

        reference_outcome, outcome, differences = "continued", "unusable", ()
        try:
            after = emulate(code, before)
        except Exception as error:
            if not is_emulator_error(error):
                raise
            reference_outcome = "error" if is_cpu_exception(error) else "unusable"
            if self.evidence is not None:
                self.evidence.finding(
                    "reference_execution", code, error, context=context
                )
        if current is not None:
            observed = "error" if reference_outcome == "error" else after
            try:
                differences = current.differences(
                    before,
                    observed,
                    on_prediction=capture_prediction
                    if self.evidence is not None
                    else None,
                    require_outcome=True,
                )
            except ComparisonUnavailable as error:
                if self.evidence is not None:
                    self.evidence.finding("comparison", code, error, context=context)
            else:
                if reference_outcome != "unusable":
                    outcome = "disagreement" if differences else "agreement"
        if outcome == "agreement":
            self.agreements += 1
        elif outcome == "disagreement":
            self.disagreements += 1
            if self.first_disagreement is None:
                self.first_disagreement = {
                    "input": {
                        "instruction_hex": code.hex(),
                        "scalars": dict(before.scalars),
                        "memory": {str(k): v for k, v in before.memory.items()},
                    },
                    "witness": dict(before.scalars),
                    "differences": list(differences),
                }
        else:
            self.unusable += 1
        if self.evidence is not None:
            recorder.capture(
                lambda: Comparison(
                    outcome,
                    prediction[0] if prediction else None,
                    StateSnapshot.capture(after) if after is not None else None,
                    reference_outcome,
                    tuple(differences),
                ),
                context=context,
            )
            recorder.sample_complete()

    def summary(self):
        return {
            **(self.first_disagreement or {}),
            "agreements": self.agreements,
            "disagreements": self.disagreements,
            "unusable": self.unusable,
            "acquisition_findings": self.acquisition_findings,
            "generation_findings": self.generation_findings,
            "fallback_allocations": dict(self.allocations),
            "input_sha256": self.digest.hexdigest(),
        }
