# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Codec-independent evidence laws, exercised with the reference backend."""

from collections.abc import Mapping
from dataclasses import dataclass
from io import BytesIO
from unittest.mock import patch

from hypothesis import given, settings, strategies as st
import pytest

from extractor.artifact import (
    Assignment,
    Declaration,
    InstructionModel,
    StepSummary,
    Target,
    TermSort,
    TypedExpr,
)
from extractor.evidence import (
    EvidenceAdapter,
    EvidenceReader,
    RunContext,
    TruncatedRecord,
    TypeRegistry,
)
from extractor.evidence_reference_json import ReferenceJSONBackend


@dataclass(frozen=True)
class Sample:
    memory: Mapping[int, int]
    vector: int
    code: bytes
    label: str | None
    alternatives: tuple[bool | int | None, ...]


SAMPLES = st.builds(
    Sample,
    memory=st.dictionaries(st.integers(0, 2**64 - 1), st.integers(0, 255), max_size=20),
    vector=st.integers(0, 2**256 - 1),
    code=st.binary(max_size=32),
    label=st.one_of(st.none(), st.text()),
    alternatives=st.lists(
        st.one_of(st.booleans(), st.integers(), st.none()), max_size=10
    ).map(tuple),
)
RUN = RunContext("a" * 40, "00000000-0000-0000-0000-000000000001")


def registry(cls=Sample):
    types = TypeRegistry()
    types.register(cls, kind="sample")
    return types


@st.composite
def expressions(draw):
    width = draw(st.sampled_from((1, 8, 32, 64, 128, 256, 512)))
    sort = TermSort.bv(width)
    leaves = st.one_of(
        st.just(TypedExpr.var("x", sort)),
        st.integers(0, 2**width - 1).map(lambda n: TypedExpr.bv_lit(width, n)),
    )
    return draw(
        st.recursive(
            leaves,
            lambda child: st.one_of(
                child.map(lambda x: TypedExpr.unary("bv_not", x)),
                st.builds(
                    lambda op, x, y: TypedExpr.binary(op, x, y),
                    st.sampled_from(("bv_add", "bv_sub", "bv_xor")),
                    child,
                    child,
                ),
            ),
            max_leaves=15,
        )
    )


@given(expressions(), st.integers(0, 2**64 - 1))
@settings(deadline=None)
def test_recursive_model_round_trip(expression, address):
    # Reconstruct through the real model constructors, including their invariants.
    pc = TypedExpr.bv_lit(64, address)
    model = InstructionModel(
        address,
        (Declaration("x", expression.sort),),
        (
            StepSummary(
                TypedExpr.bool_lit(True),
                (Assignment("x", expression),),
                Target("address", address),
                pc,
            ),
        ),
    )
    codec = ReferenceJSONBackend().prepare(registry(InstructionModel).schemas()[0])
    decoded = codec.decode(codec.encode(model))
    assert decoded == model
    assert decoded.to_data() == model.to_data()


@given(st.lists(SAMPLES, min_size=1, max_size=12), st.integers(0, 2**64 - 1))
@settings(deadline=None)
def test_stream_round_trip_and_replay_identity(values, timestamp):
    stream, types = BytesIO(), registry()
    writer = EvidenceAdapter(
        backend=ReferenceJSONBackend(),
        types=types,
        run=RUN,
        output=stream,
        clock=lambda: timestamp,
    )
    ids = []
    # Preparing codecs is the only point at which annotation inspection is allowed.
    with patch(
        "extractor.evidence_reference_json.get_type_hints", side_effect=AssertionError
    ):
        for value in values:
            ids.append(writer.emit(value, context=ids[-1] if ids else None))
    writer.flush()
    reader = EvidenceReader(
        BytesIO(stream.getvalue()), backend=ReferenceJSONBackend(), types=types
    )
    records = list(reader)
    assert [r.value for r in records] == values
    # bool and int equality alone would miss a lost union discriminator.
    assert [[type(v) for v in r.value.alternatives] for r in records] == [
        [type(v) for v in sample.alternatives] for sample in values
    ]
    assert [r.id for r in records] == ids
    assert [r.context for r in records] == [None, *ids[:-1]]
    assert all(r.timestamp_ns == timestamp for r in records)
    assert reader.manifest["commit"] == RUN.commit
    assert reader.manifest["invocation_id"] == RUN.invocation_id
    replay = list(
        EvidenceReader(
            BytesIO(stream.getvalue()), backend=ReferenceJSONBackend(), types=types
        )
    )
    assert replay == records


@given(SAMPLES, SAMPLES, st.data())
@settings(deadline=None)
def test_truncated_final_record_preserves_completed_records(first, second, data):
    stream, types = BytesIO(), registry()
    writer = EvidenceAdapter(
        backend=ReferenceJSONBackend(), types=types, run=RUN, output=stream
    )
    first_id = writer.emit(first)
    boundary = stream.tell()
    writer.emit(second)
    cut = data.draw(st.integers(boundary + 1, stream.tell() - 1))
    records = iter(
        EvidenceReader(
            BytesIO(stream.getvalue()[:cut]),
            backend=ReferenceJSONBackend(),
            types=types,
        )
    )
    complete = next(records)
    assert complete.id == first_id and complete.value == first
    with pytest.raises(TruncatedRecord):
        next(records)


class RuntimeResult:
    def __init__(self, sample):
        self.sample = sample
        self.runtime_handle = object()


@given(SAMPLES)
def test_projection_preserves_semantics_without_runtime_handle(sample):
    types = TypeRegistry()
    types.register(
        RuntimeResult,
        kind="runtime_result",
        representation=Sample,
        project=lambda value: value.sample,
        restore=RuntimeResult,
    )
    codec = ReferenceJSONBackend().prepare(types.schemas()[0])
    original = RuntimeResult(sample)
    recovered = codec.decode(codec.encode(original))
    assert recovered.sample == original.sample
    assert recovered.runtime_handle is not original.runtime_handle


@dataclass(frozen=True)
class Blob:
    payload: bytes


class RawBackend:
    name = "test.raw.v1"

    def prepare(self, schema):
        assert schema.python_type is Blob

        class Codec:
            def encode(self, value):
                assert type(value) is Blob  # No mandatory dict/JSON intermediate.
                return value.payload

            def decode(self, data):
                return Blob(data)

        return Codec()


@given(st.binary())
def test_backend_receives_typed_object_and_owns_payload_encoding(payload):
    stream, types = BytesIO(), registry(Blob)
    writer = EvidenceAdapter(backend=RawBackend(), types=types, run=RUN, output=stream)
    writer.emit(Blob(payload))
    assert [
        r.value
        for r in EvidenceReader(
            BytesIO(stream.getvalue()), backend=RawBackend(), types=types
        )
    ] == [Blob(payload)]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
