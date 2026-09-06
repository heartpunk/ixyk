# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cumulative outcomes and shared fallback scheduling for differential fuzzing."""

import hashlib
from time import perf_counter_ns

from extractor.acquisition_errors import EXPECTED_ACQUISITION
from extractor.evidence_events import Comparison, FuzzInput, StateSnapshot
from extractor.extractor import extract
from extractor.fuzzer import ComparisonUnavailable, CompiledModel, emulate
from extractor.runtime import load_shellcode
from extractor.unicorn_boundary import is_cpu_exception, is_emulator_error


class Campaign:
    def __init__(self, instruction, evidence=None, *, fixed_model=None):
        self.instruction, self.evidence = instruction, evidence
        self.fixed_model = (
            CompiledModel(fixed_model) if fixed_model is not None else None
        )
        self.pool = []
        self.pool_index = 0
        self.allocations = {}
        self.model_id = None
        self.route = "unavailable"
        self.agreements = self.disagreements = self.unusable = 0
        self.acquisition_findings = self.generation_findings = 0
        self.first_disagreement = None
        self.digest = hashlib.sha256()

    def form_unavailable(self, form, error):
        self.generation_findings += 1
        if self.evidence is not None:
            self.evidence.finding(f"generation:form:{form}", self.instruction, error)

    def select(self, code, source, sample):
        context = f"sample:{self.instruction.hex()}:{sample}"
        if self.fixed_model is not None:
            self.route = "fallback"
            if self.evidence is not None:
                self.model_id = self.evidence.model(
                    code, self.fixed_model.artifact, "direct", context=context
                )
            return code, self.fixed_model.artifact.source, self.fixed_model
        if not self.pool:
            retained = []
            stage = ["acquisition", code]

            def on_model(encoding, model, route):
                if route == "direct":
                    retained.append((encoding, model))
                if self.evidence is not None:
                    identifier = self.evidence.model(
                        encoding, model, route, context=context
                    )
                    if route == "generalized":
                        self.model_id = identifier

            def on_stage(name, encoding):
                stage[:] = [name, encoding]

            def on_finding(name, encoding, error):
                self.acquisition_findings += 1
                if self.evidence is not None:
                    self.evidence.finding(name, encoding, error, context=context)

            try:
                model = extract(
                    load_shellcode(code, source),
                    source,
                    on_model=on_model,
                    on_stage=on_stage,
                    on_finding=on_finding,
                )
            except EXPECTED_ACQUISITION as error:
                self.acquisition_findings += 1
                if self.evidence is not None:
                    self.evidence.finding(stage[0], stage[1], error, context=context)
                self.pool = [
                    (encoding, model, CompiledModel(model))
                    for encoding, model in retained
                ]
                if not self.pool:
                    self.model_id, self.route = None, "unavailable"
                    return code, source, None
            else:
                self.route = "generalized"
                return code, source, CompiledModel(model)
        # The first failure establishes the pool. Subsequent samples spend the
        # remaining *existing* budget round-robin; they do not start sub-runs.
        code, model, compiled = self.pool[self.pool_index % len(self.pool)]
        self.pool_index += 1
        self.allocations[code.hex()] = self.allocations.get(code.hex(), 0) + 1
        self.route = "fallback"
        if self.evidence is not None:
            self.model_id = self.evidence.model(code, model, "direct", context=context)
        return code, model.source, compiled

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
