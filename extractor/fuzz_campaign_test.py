# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from collections import Counter
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

from hypothesis import given, settings, strategies as st
import pytest

from extractor import z3_runtime as _z3_runtime  # noqa: F401
from extractor import fuzz_campaign as campaign_module
from extractor.artifact import InstructionModel
from extractor.evidence import EvidenceReader, RunContext
from extractor.evidence_events import (
    Comparison,
    EvidenceHooks,
    FuzzInput,
    evidence_types,
)
from extractor.evidence_recording import BackgroundRecorder
from extractor.evidence_reference_json import ReferenceJSONBackend
from extractor.extractor import extract
from extractor.fuzz_campaign import Campaign
from extractor.fuzzer import ConcreteState, CompiledModel, _input_state, emulate
from extractor.amd64_state import FLAG_NAMES, GPR64, YMM256
from extractor.operand_slots import OperandDecodeError
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
    ):
        selected = [campaign.select(b"\xc3", 8192, i)[0] for i in range(budget)]
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
        side_effect=OperandDecodeError("forced AU failure"),
    ):
        with pytest.raises(OperandDecodeError, match="forced AU"):
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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
