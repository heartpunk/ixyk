# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from collections import Counter
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

from hypothesis import given, settings, strategies as st
import pytest

from antiunification.algebra import AlgebraError
from extractor import z3_runtime as _z3_runtime  # noqa: F401
from extractor import fuzz_campaign as campaign_module
from extractor.artifact import InstructionModel
from extractor.evidence import EvidenceReader, RunContext
from extractor.evidence_events import (
    Comparison,
    EvidenceHooks,
    FuzzInput,
    ToolFailure,
    evidence_types,
)
from extractor.evidence_recording import BackgroundRecorder
from extractor.evidence_reference_json import ReferenceJSONBackend
from extractor.extractor import extract
from extractor.fuzz_campaign import Campaign
from extractor.fuzzer import (
    ConcreteState,
    CompiledModel,
    InputLayout,
    _input_state,
    emulate,
    fuzz,
)
from extractor.amd64_state import FLAG_NAMES, GPR64, YMM256
from extractor.operand_slots import OperandDecodeError
from extractor import runtime
from extractor.runtime import load_shellcode
from extractor.unicorn_boundary import unicorn_constant
import unicorn


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


def test_forced_au_failure_preserves_real_direct_models():
    code, source = bytes.fromhex("4801d8"), 4096
    retained = []
    with patch(
        "antiunification.many.antiunify_many",
        side_effect=AlgebraError("sparse state update has duplicate keys"),
    ):
        with pytest.raises(OperandDecodeError, match="AU algebra.*duplicate keys"):
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
    from extractor import xed
    from extractor.extractor import _extract_concrete
    import antiunification.many as au

    codes = [
        bytes.fromhex(h) for h in (["4801d8", "4801c8"] if fallback else ["4801d8"])
    ]
    models = [
        _extract_concrete(load_shellcode(code, 0x400000), 0x400000) for code in codes
    ]
    acquisition = dict(
        schema="ixyk.instruction_acquisition.v1",
        instruction_hex=codes[0].hex(),
        status="acquisition_error" if fallback else "pass",
        model_route="direct" if fallback else "generalized",
        retained_models=[
            dict(instruction_hex=c.hex(), model=m.to_data())
            for c, m in zip(codes, models)
        ],
        findings=[],
    )
    stream = BytesIO()
    recorder = (
        BackgroundRecorder(
            backend=ReferenceJSONBackend(),
            types=evidence_types(),
            run=RunContext("a" * 40, "frozen-test"),
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
                (campaign_module, "load_shellcode"),
                (runtime, "load_shellcode"),
                (CompiledModel, "__init__"),
                (au, "antiunify_many"),
            ]:
                stack.enter_context(
                    patch.object(
                        target,
                        name,
                        side_effect=AssertionError("forbidden hot-loop call"),
                    )
                )

        stack.enter_context(patch.object(Campaign, "prepare", prepare_checked))
        stack.enter_context(patch.object(campaign_module, "emulate", emulate_checked))
        try:
            report = fuzz(
                models[0],
                codes[0],
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
    assert [code for code, _ in observed] == [codes[i % len(codes)] for i in range(17)]
    assert {state.scalars["rip"] for _, state in observed} == {0x400000}
    assert len({tuple(state.scalars.items()) for _, state in observed}) > 1
    assert len({tuple(state.memory.items()) for _, state in observed}) > 1
    if fallback:
        assert report["fallback_allocations"] == {codes[0].hex(): 9, codes[1].hex(): 8}
    else:
        assert report["fallback_allocations"] == {}
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
        assert sum(isinstance(r.value, InstructionModel) for r in records) == len(
            models
        )


def test_unavailable_acquisition_is_reported_without_new_discovery():
    acquisition = dict(
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
