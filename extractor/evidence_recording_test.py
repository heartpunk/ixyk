# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from extractor.evidence import EvidenceReader, RunContext
from extractor.evidence_events import (
    AttemptContext,
    Finding,
    FuzzInput,
    StateSnapshot,
    evidence_types,
)
from extractor.evidence_recording import BackgroundRecorder
from extractor.evidence_reference_json import ReferenceJSONBackend

RUN = RunContext("a" * 40, "00000000-0000-0000-0000-000000000001")
STATES = st.builds(
    StateSnapshot,
    scalars=st.dictionaries(
        st.sampled_from(("rax", "rip", "ymm0")), st.integers(0, 2**256 - 1)
    ).map(lambda d: tuple(d.items())),
    memory=st.dictionaries(
        st.integers(0, 2**64 - 1), st.integers(0, 255), max_size=16
    ).map(lambda d: tuple(d.items())),
)
ATTEMPTS = st.builds(
    AttemptContext,
    operation=st.sampled_from(("constructor-preflight", "generation", "comparison")),
    constructor_id=st.one_of(st.none(), st.integers(0, 20_000)),
    case_index=st.one_of(st.none(), st.integers(0, 100)),
    domains=st.one_of(
        st.none(),
        st.lists(
            st.tuples(
                st.lists(st.integers(0, 500), max_size=8).map(tuple),
                st.integers(-(2**31), 0),
                st.integers(0, 2**32),
                st.booleans(),
            ),
            max_size=6,
        ).map(tuple),
    ),
    alias_groups=st.one_of(
        st.none(),
        st.lists(st.lists(st.integers(0, 8), max_size=4).map(tuple), max_size=4).map(
            tuple
        ),
    ),
    arguments=st.one_of(
        st.none(), st.lists(st.integers(0, 2**64 - 1), max_size=8).map(tuple)
    ),
    source=st.one_of(st.none(), st.integers(0, 2**64 - 1)),
    encoding=st.one_of(st.none(), st.binary(max_size=15)),
    model_ids=st.lists(st.text(min_size=1, max_size=20), max_size=8).map(tuple),
    fuzz_input_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
)


@given(ATTEMPTS)
@settings(deadline=None)
def test_failure_context_round_trip(attempt):
    stream = BytesIO()
    recorder = BackgroundRecorder(
        backend=ReferenceJSONBackend(), types=evidence_types(), run=RUN, output=stream
    )
    value = Finding("generation", b"\x90", "EncodingError", "rejected", attempt)
    identifier = recorder.emit(value, context=attempt.fuzz_input_id)
    recorder.close()
    reader = EvidenceReader(
        BytesIO(stream.getvalue()),
        backend=ReferenceJSONBackend(),
        types=evidence_types(),
    )
    records = list(reader)
    assert [(record.id, record.context, record.value) for record in records] == [
        (identifier, attempt.fuzz_input_id, value)
    ]
    assert reader.manifest["commit"] == RUN.commit
    assert reader.manifest["invocation_id"] == RUN.invocation_id


@given(
    st.lists(STATES, min_size=1, max_size=20),
    st.integers(1, 5),
    st.integers(0, 2**64 - 1),
)
@settings(deadline=None)
def test_background_round_trip(states, capacity, timestamp):
    stream = BytesIO()
    recorder = BackgroundRecorder(
        backend=ReferenceJSONBackend(),
        types=evidence_types(),
        run=RUN,
        output=stream,
        capacity=capacity,
    )
    values = [
        FuzzInput(i, b"\xc3", state, None, "unavailable")
        for i, state in enumerate(states)
    ]
    ids = []
    with patch("extractor.evidence_recording.time_ns", return_value=timestamp):
        for value in values:
            ids.append(recorder.emit(value, context=ids[-1] if ids else None))
            recorder.sample_complete()
    recorder.close()
    recorder.close()
    reader = EvidenceReader(
        BytesIO(stream.getvalue()),
        backend=ReferenceJSONBackend(),
        types=evidence_types(),
    )
    records = list(reader)
    assert [r.value for r in records] == values
    assert [r.id for r in records] == ids
    assert [r.context for r in records] == [None, *ids[:-1]]
    assert all(r.timestamp_ns == timestamp for r in records)
    assert reader.manifest["commit"] == RUN.commit
    assert reader.manifest["invocation_id"] == RUN.invocation_id
    assert recorder.metrics.records == recorder.metrics.flushes == len(values)
    assert recorder.metrics.queue_high_water <= capacity
    assert recorder.metrics.framed_bytes == len(stream.getvalue())
    assert 0 < recorder.metrics.payload_bytes < recorder.metrics.framed_bytes
    assert not recorder._worker.is_alive()
    with pytest.raises(ValueError, match="closed"):
        recorder.emit(values[0])


@given(STATES)
@settings(deadline=None)
def test_capture_detaches_mutable_state(state):
    live = SimpleNamespace(scalars=dict(state.scalars), memory=dict(state.memory))
    stream = BytesIO()
    recorder = BackgroundRecorder(
        backend=ReferenceJSONBackend(), types=evidence_types(), run=RUN, output=stream
    )
    recorder.capture(
        lambda: FuzzInput(1, b"\xc3", StateSnapshot.capture(live), None, "unavailable")
    )
    live.scalars.clear()
    live.memory.clear()
    recorder.close()
    records = list(
        EvidenceReader(
            BytesIO(stream.getvalue()),
            backend=ReferenceJSONBackend(),
            types=evidence_types(),
        )
    )
    assert records[0].value.before == state


def test_worker_failure_reaches_close():
    class BrokenBackend:
        name = "broken"

        def prepare(self, schema):
            class Codec:
                def encode(self, value):
                    raise OSError("test disk/codec failure")

            return Codec()

    recorder = BackgroundRecorder(
        backend=BrokenBackend(),
        types=evidence_types(),
        run=RUN,
        output=BytesIO(),
        capacity=1,
    )
    value = FuzzInput(1, b"\xc3", StateSnapshot((), ()), None, "unavailable")
    try:
        recorder.emit(value)
    except RuntimeError:
        pass  # The worker may report the error before emit returns.
    with pytest.raises(RuntimeError, match="background evidence") as failure:
        recorder.close()
    assert isinstance(failure.value.__cause__, OSError)
    recorder._worker.join(timeout=1)
    assert not recorder._worker.is_alive()


@given(st.integers(1, 8))
@settings(max_examples=8, deadline=None)
def test_cyclic_finalizers_stay_on_producer_thread(count):
    import gc
    from threading import get_ident

    owner = get_ident()
    finalized = []
    enabled, limits = gc.isenabled(), gc.get_threshold()

    class NativeOwner:
        def __init__(self):
            self.cycle = self

        def __del__(self):
            finalized.append(get_ident())

    recorder = BackgroundRecorder(
        backend=ReferenceJSONBackend(),
        types=evidence_types(),
        run=RUN,
        output=BytesIO(),
    )
    try:
        assert not gc.isenabled()
        gc.set_threshold(1, 1, 1)
        for i in range(count):
            NativeOwner()
            recorder.emit(
                FuzzInput(i, b"\x90", StateSnapshot((), ()), None, "unavailable")
            )
        gc.collect()
    finally:
        recorder.close()
        gc.set_threshold(*limits)
    assert finalized == [owner] * count
    assert gc.isenabled() == enabled


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
