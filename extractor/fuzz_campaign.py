# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cumulative outcomes and shared fallback scheduling for differential fuzzing."""

import hashlib
from dataclasses import dataclass
from time import perf_counter_ns
from typing import Literal

from extractor.acquisition_errors import EXPECTED_ACQUISITION
from extractor.evidence_events import (
    AttemptContext,
    Comparison,
    Finding,
    FuzzInput,
    StateSnapshot,
)
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
    case: object | None = None
    values_strategy: object | None = None


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
            self.evidence.finding(
                f"generation:form:{form}",
                self.instruction,
                error,
                attempt=AttemptContext(
                    operation="form-generation", encoding=self.instruction
                ),
            )

    def prepare(self, *, source=0x400000, acquisition=None, vary_encodings=False):
        if self.prepared:
            raise RuntimeError("campaign models are already frozen")
        if vary_encodings:
            self._prepare_cases(source, acquisition)
            return
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
                self.evidence.finding(
                    name,
                    code,
                    error,
                    context="preparation",
                    attempt=AttemptContext(
                        operation=name,
                        source=source,
                        encoding=code,
                        model_ids=tuple(identifiers.values()),
                    ),
                )

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
                    self.evidence.recorder.emit(
                        Finding(
                            finding["stage"],
                            bytes.fromhex(finding["instruction_hex"]),
                            finding["error_kind"],
                            finding["message"],
                            AttemptContext.from_data(finding.get("attempt")),
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

    def _prepare_cases(self, source, acquisition):
        from extractor.evidence_events import GeneralizationInputs
        from extractor.prepared_cases import PreparedCase, prepare_catalog

        def on_model(code, model, route):
            if self.evidence is not None:
                return self.evidence.model(code, model, route, context="preparation")
            return None

        def on_finding(stage, code, error, attempt=None):
            self.acquisition_findings += 1
            if self.evidence is not None:
                self.evidence.finding(
                    stage,
                    code,
                    error,
                    context="preparation",
                    attempt=attempt,
                )

        if acquisition is not None and "prepared_cases" in acquisition:
            cases = [PreparedCase.from_data(c) for c in acquisition["prepared_cases"]]
            for finding in acquisition.get("findings", ()):
                self.acquisition_findings += 1
                if self.evidence is not None:
                    self.evidence.recorder.emit(
                        Finding(
                            finding["stage"],
                            bytes.fromhex(finding["instruction_hex"]),
                            finding["error_kind"],
                            finding["message"],
                            AttemptContext.from_data(finding.get("attempt")),
                        ),
                        context="preparation",
                    )
        else:
            cases = prepare_catalog(
                self.instruction, source, on_model=on_model, on_finding=on_finding
            )
        prepared = []
        seen_fallback = set()
        for case in cases:
            identifiers = []
            for code, decoded, model in case.observations:
                identifier = (
                    self.evidence.model(code, model, "direct", context="preparation")
                    if self.evidence
                    else None
                )
                identifiers.append((code, model.source, identifier))
            if case.template is not None and all(case.comparable):
                code, decoded, model = case.observations[0]
                identifier = (
                    self.evidence.recorder.emit(
                        GeneralizationInputs(
                            case.arguments.form["id"], tuple(identifiers)
                        ),
                        context="preparation",
                    )
                    if self.evidence
                    else None
                )
                prepared.append(
                    PreparedModel(
                        code,
                        model.source,
                        CompiledModel(model),
                        InputLayout.from_decoded(decoded),
                        "generalized",
                        identifier,
                        case,
                        case.arguments.strategy(),
                    )
                )
            else:
                for (code, decoded, model), (_, _, identifier), comparable in zip(
                    case.observations, identifiers, case.comparable, strict=True
                ):
                    if not comparable or (code, model.source) in seen_fallback:
                        continue
                    seen_fallback.add((code, model.source))
                    prepared.append(
                        PreparedModel(
                            code,
                            model.source,
                            CompiledModel(model),
                            InputLayout.from_decoded(decoded),
                            "fallback",
                            identifier,
                        )
                    )
        self.models = tuple(prepared)
        self.prepared = True

    def bind(self, selected, data, source):
        from hypothesis import assume

        from extractor.evidence_events import ModelInstantiation
        from extractor.xed import EncodingError

        if selected.case is None:
            return selected
        values = data.draw(selected.values_strategy)
        try:
            code, decoded, model = selected.case.instantiate(values, source)
        except EncodingError as error:
            self.generation_findings += 1
            if self.evidence is not None:
                arguments = selected.case.arguments
                self.evidence.finding(
                    "generation:sample",
                    selected.code,
                    error,
                    context=selected.model_id,
                    attempt=AttemptContext(
                        operation="fuzz-generation",
                        constructor_id=arguments.form["id"],
                        domains=tuple(
                            (d.choices, d.low, d.high, d.register)
                            for d in arguments.domains
                        ),
                        alias_groups=arguments.groups,
                        arguments=values,
                        source=source,
                        model_ids=(selected.model_id,) if selected.model_id else (),
                    ),
                )
            assume(False)
        identifier = (
            self.evidence.recorder.emit(
                ModelInstantiation(selected.model_id, values, source),
                context=selected.model_id,
            )
            if self.evidence
            else None
        )
        self.model_id = identifier
        return PreparedModel(
            code,
            source,
            CompiledModel(model),
            InputLayout.from_decoded(decoded),
            "generalized",
            identifier,
        )

    def select(self, sample):
        if not self.prepared:
            raise RuntimeError("campaign must be prepared before sampling")
        if not self.models:
            raise RuntimeError("campaign has no executable models")
        selected = self.models[(sample - 1) % len(self.models)]
        self.model_id, self.route = selected.model_id, selected.route
        if selected.route == "fallback":
            key = f"{selected.code.hex()}@{selected.source:x}"
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
                    "reference_execution",
                    code,
                    error,
                    context=context,
                    attempt=AttemptContext(
                        "reference-execution",
                        source=before.scalars.get("rip"),
                        encoding=code,
                        model_ids=(self.model_id,) if self.model_id else (),
                        fuzz_input_id=context,
                    ),
                )
        if current is not None:
            observed = "error" if reference_outcome == "error" else after
            try:
                differences = current.differences(
                    before,
                    observed,
                    on_prediction=(
                        capture_prediction if self.evidence is not None else None
                    ),
                    require_outcome=True,
                )
            except ComparisonUnavailable as error:
                if self.evidence is not None:
                    self.evidence.finding(
                        "comparison",
                        code,
                        error,
                        context=context,
                        attempt=AttemptContext(
                            "comparison",
                            source=before.scalars.get("rip"),
                            encoding=code,
                            model_ids=(self.model_id,) if self.model_id else (),
                            fuzz_input_id=context,
                        ),
                    )
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
