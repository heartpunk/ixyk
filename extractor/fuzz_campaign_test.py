# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from collections import Counter
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import unicorn
from hypothesis import given, settings
from hypothesis import strategies as st

from antiunification.algebra import AlgebraError
from extractor import fuzz_campaign as campaign_module
from extractor import runtime
from extractor import z3_runtime as _z3_runtime  # noqa: F401
from extractor.amd64_state import FLAG_NAMES, GPR64, YMM256
from extractor.artifact import InstructionModel
from extractor.evidence import EvidenceReader, RunContext
from extractor.evidence_events import (
    Comparison,
    EvidenceHooks,
    Finding,
    FuzzInput,
    ToolFailure,
    evidence_types,
)
from extractor.evidence_recording import BackgroundRecorder
from extractor.evidence_reference_json import ReferenceJSONBackend
from extractor.extractor import extract
from extractor.fuzz_campaign import Campaign
from extractor.fuzzer import (
    CompiledModel,
    ConcreteState,
    InputLayout,
    _input_state,
    emulate,
    fuzz,
)
from extractor.operand_slots import OperandDecodeError
from extractor.runtime import load_shellcode
from extractor.unicorn_boundary import unicorn_constant


@given(st.integers(1, 10), st.integers(1, 100))
@settings(deadline=None)
def test_fallback_divides_one_budget_across_retained_variants(variants, budget):
    retained = [
        (bytes((index,)), SimpleNamespace(source=4096)) for index in range(variants)
    ]

    def extraction(project, source, *, on_model, on_stage, on_finding):
        for code, model in retained:
            on_model(code, model, "direct")
        on_stage("generalization", b"\xc3")
        raise OperandDecodeError("forced AU failure")

    campaign = Campaign(b"\xc3")
    with (
        patch.object(campaign_module, "extract", side_effect=extraction) as acquire,
        patch.object(campaign_module, "load_shellcode"),
        patch.object(campaign_module, "CompiledModel", side_effect=lambda model: model),
        patch.object(InputLayout, "prepare", return_value=None),
    ):
        campaign.prepare(source=8192)
        selected = [campaign.select(i + 1).code for i in range(budget)]
    counts = Counter(selected)
    allocation = [counts[code] for code, _ in retained]
    assert sum(allocation) == budget
    assert max(allocation) - min(allocation) <= 1
    assert sum(campaign.allocations.values()) == budget
    assert acquire.call_count == 1


@given(
    st.lists(
        st.sampled_from(("agreement", "disagreement", "unusable")),
        min_size=2,
        max_size=20,
    )
)
@settings(deadline=None)
def test_outcomes_continue_and_recording_does_not_change_comparisons(outcomes):
    state = ConcreteState({"rip": 4096}, {4096: 0xC3})
    stream = BytesIO()
    recorder = BackgroundRecorder(
        backend=ReferenceJSONBackend(),
        types=evidence_types(),
        run=RunContext("a" * 40, "test-invocation"),
        output=stream,
        capacity=2,
    )
    summaries = []
    for hooks in (None, EvidenceHooks(recorder)):
        campaign = Campaign(b"\xc3", hooks)
        for index, outcome in enumerate(outcomes):
            model = SimpleNamespace(
                differences=lambda *args, outcome=outcome, **kw: (
                    ("rax differs",) if outcome == "disagreement" else ()
                )
            )
            error = (
                unicorn.UcError(unicorn_constant("UC_ERR_RESOURCE"))
                if outcome == "unusable"
                else None
            )
            with patch.object(
                campaign_module, "emulate", side_effect=error, return_value=state
            ):
                campaign.compare(model, b"\xc3", state, index)
        summaries.append(campaign.summary())
    recorder.close()
    assert summaries[0] == summaries[1]
    assert summaries[0]["agreements"] == outcomes.count("agreement")
    assert summaries[0]["disagreements"] == outcomes.count("disagreement")
    assert summaries[0]["unusable"] == outcomes.count("unusable")
    records = list(
        EvidenceReader(
            BytesIO(stream.getvalue()),
            backend=ReferenceJSONBackend(),
            types=evidence_types(),
        )
    )
    inputs = {r.id: r for r in records if isinstance(r.value, FuzzInput)}
    comparisons = [r for r in records if isinstance(r.value, Comparison)]
    assert [r.value.outcome for r in comparisons] == outcomes
    assert all(r.context in inputs for r in comparisons)
    assert len(inputs) == len(outcomes)
    failures = [r for r in records if isinstance(r.value, Finding)]
    assert len(failures) == outcomes.count("unusable")
    assert all(
        failure.value.attempt.fuzz_input_id == failure.context
        and failure.value.attempt.encoding == b"\xc3"
        for failure in failures
    )


def test_forced_au_failure_preserves_real_direct_models():
    code, source = bytes.fromhex("4801d8"), 4096
    retained = []
    with (
        patch(
            "antiunification.many.antiunify_many",
            side_effect=AlgebraError("sparse state update has duplicate keys"),
        ),
        pytest.raises(OperandDecodeError, match="AU algebra.*duplicate keys"),
    ):
        extract(
            load_shellcode(code, source),
            source,
            on_model=lambda encoding, model, route: retained.append(
                (encoding, model, route)
            ),
        )
    direct = [
        (encoding, model) for encoding, model, route in retained if route == "direct"
    ]
    assert len(direct) >= 2
    assert all(isinstance(model, InstructionModel) for _, model in direct)
    # Retained semantic models remain executable by the same comparator.
    encoding, model = direct[0]
    registers = tuple(8192 if name == "rsp" else 0 for name in GPR64 + YMM256)
    before = _input_state(
        encoding, source, {}, bytes(32), registers, [False] * len(FLAG_NAMES), True
    )
    after = emulate(encoding, before)
    compiled = CompiledModel(model)
    predictions = []
    plain = compiled.differences(before, after, require_outcome=True)
    recorded = compiled.differences(
        before,
        after,
        on_prediction=lambda factory: predictions.append(factory()),
        require_outcome=True,
    )
    assert recorded == plain == ()
    assert len(predictions) == 1
    assert dict(predictions[0].scalars) == after.scalars
    memory = predictions[0].memory
    assert memory.index_width == 64
    assert memory.value_width == 8
    assert memory.default == 0
    assert dict(memory.entries) == {k: v for k, v in after.memory.items() if v}


@pytest.mark.parametrize(
    "operation,tool",
    [("loader", "angr.load_shellcode"), ("lifter", "angr.factory.block")],
)
def test_preparation_failure_is_retained_without_retrying_in_samples(operation, tool):
    from extractor.tool_errors import AngrOperationError, ShellcodeLoadError

    stream = BytesIO()
    recorder = BackgroundRecorder(
        backend=ReferenceJSONBackend(),
        types=evidence_types(),
        run=RunContext("a" * 40, "test-invocation"),
        output=stream,
    )
    campaign = Campaign(b"\x90", EvidenceHooks(recorder))
    error = (
        ShellcodeLoadError(ValueError("failed"))
        if operation == "loader"
        else AngrOperationError(tool, ValueError("failed"))
    )
    with patch.object(campaign_module, "load_shellcode", side_effect=error) as acquire:
        campaign.prepare()
        assert campaign.models == ()
        with pytest.raises(RuntimeError, match="already frozen"):
            campaign.prepare()
        with pytest.raises(RuntimeError, match="no executable models"):
            campaign.select(1)
        assert acquire.call_count == 1
    recorder.close()
    failures = [
        r.value
        for r in EvidenceReader(
            BytesIO(stream.getvalue()),
            backend=ReferenceJSONBackend(),
            types=evidence_types(),
        )
        if isinstance(r.value, ToolFailure)
    ]
    assert len(failures) == campaign.acquisition_findings == 1
    assert failures[0].tool == tool
    assert failures[0].before is None


@pytest.mark.parametrize("recording", [False, True])
@pytest.mark.parametrize("fallback", [False, True])
def test_frozen_campaign_has_no_acquisition_in_sampling(recording, fallback):
    from contextlib import ExitStack

    from extractor import prepared_cases, xed
    from extractor.constructor_inputs import ArgumentCase, Domain
    from extractor.evidence_events import GeneralizationInputs, ModelInstantiation
    from extractor.extractor import _extract_concrete
    from extractor.prepared_cases import PreparedCase, generalize

    form = next(
        f
        for f in xed._invoke("forms", "ADD")
        if "_APX" not in f["form"]
        and [a["kind"] for a in f["args"]] == ["gpr64", "gpr64"]
        and all(a["name"].startswith("reg") for a in f["args"])
    )
    bank = {r["name"]: r["value"] for r in xed.registers()}
    domain = Domain(
        tuple(bank[r] for r in ["RAX", "RBX", "RCX", "RDX", "R8", "R9"]), register=True
    )
    arguments = ArgumentCase(form, (domain, domain), ((0,), (1,)))
    requests = [
        ((bank["RAX"], bank["RBX"]), 0x400000),
        ((bank["RCX"], bank["RBX"]), 0x400000),
    ]
    if not fallback:
        requests += [
            ((bank["RAX"], bank["RDX"]), 0x400000),
            ((bank["RAX"], bank["RBX"]), 0xFFFFFEDCBA987654),
        ]
    observations = []
    for values, source in requests:
        decoded = xed.encode_constructor(form["id"], values)
        code = bytes.fromhex(decoded["hex"])
        observations.append(
            (code, decoded, _extract_concrete(load_shellcode(code, source), source))
        )
    case = PreparedCase(
        arguments,
        tuple(observations),
        None if fallback else generalize(observations),
        (True,) * len(observations),
    )
    acquisition = {"prepared_cases": [case.to_data()], "findings": []}
    stream = BytesIO()
    recorder = (
        BackgroundRecorder(
            backend=ReferenceJSONBackend(),
            types=evidence_types(),
            run=RunContext("a" * 40, "prepared-test"),
            output=stream,
        )
        if recording
        else None
    )
    prepare = Campaign.prepare
    observed = []
    original_emulate = campaign_module.emulate

    def emulate_checked(code, before):
        observed.append((code, before))
        return original_emulate(code, before)

    with ExitStack() as stack:

        def prepare_checked(self, **kwargs):
            prepare(self, **kwargs)
            for target, name in [
                (xed, "_invoke"),
                (campaign_module, "extract"),
                (runtime, "load_shellcode"),
                (prepared_cases, "_extract_concrete"),
                (prepared_cases, "antiunify_many"),
            ]:
                stack.enter_context(
                    patch.object(
                        target,
                        name,
                        side_effect=AssertionError("forbidden hot-loop acquisition"),
                    )
                )

        stack.enter_context(patch.object(Campaign, "prepare", prepare_checked))
        stack.enter_context(patch.object(campaign_module, "emulate", emulate_checked))
        try:
            report = fuzz(
                observations[0][2],
                observations[0][0],
                17,
                max_executions=17,
                vary_inputs=True,
                continue_on_findings=True,
                acquisition=acquisition,
                evidence=EvidenceHooks(recorder) if recorder else None,
            )
        finally:
            if recorder:
                recorder.close()
    assert report["executions"] == len(observed) == 17
    if fallback:
        assert Counter(code for code, _ in observed) == {
            observations[0][0]: 9,
            observations[1][0]: 8,
        }
        assert report["fallback_allocations"] == {
            f"{observations[0][0].hex()}@400000": 9,
            f"{observations[1][0].hex()}@400000": 8,
        }
    else:
        assert len({code for code, _ in observed}) > 1
        assert len({state.scalars["rip"] for _, state in observed}) > 1
        assert report["fallback_allocations"] == {}
    assert len({tuple(state.scalars.items()) for _, state in observed}) > 1
    assert len({tuple(state.memory.items()) for _, state in observed}) > 1
    assert report["agreements"] + report["disagreements"] + report["unusable"] == 17
    if recorder:
        records = list(
            EvidenceReader(
                BytesIO(stream.getvalue()),
                backend=ReferenceJSONBackend(),
                types=evidence_types(),
            )
        )
        assert sum(isinstance(r.value, FuzzInput) for r in records) == 17
        assert sum(isinstance(r.value, Comparison) for r in records) == 17
        if not fallback:
            templates = {
                r.id for r in records if isinstance(r.value, GeneralizationInputs)
            }
            bindings = {
                r.id: r.value
                for r in records
                if isinstance(r.value, ModelInstantiation)
            }
            assert all(
                value.generalization_id in templates for value in bindings.values()
            )
            assert all(
                r.value.model_id in bindings
                for r in records
                if isinstance(r.value, FuzzInput)
            )


def test_unavailable_acquisition_is_reported_without_new_discovery():
    acquisition = dict(
        prepared_cases=[],
        schema="ixyk.instruction_acquisition.v1",
        instruction_hex="90",
        status="unsupported",
        model_route=None,
        retained_models=[],
        findings=[
            dict(
                stage="generalization",
                instruction_hex="90",
                error_kind="OperandDecodeError",
                message="no model",
            )
        ],
    )
    with patch.object(
        campaign_module, "extract", side_effect=AssertionError("new discovery")
    ):
        report = fuzz(
            None,
            b"\x90",
            17,
            vary_inputs=True,
            continue_on_findings=True,
            acquisition=acquisition,
        )
    assert report["executions"] == 0
    assert report["status"] == "incomplete"
    assert report["acquisition_findings"] == 1
    assert report["prepared_models"] == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
