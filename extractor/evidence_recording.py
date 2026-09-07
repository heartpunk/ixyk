# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded background recording and measurements shared by every codec."""

from dataclasses import dataclass
import gc
from queue import Full, Queue
from threading import Thread
from time import perf_counter_ns, thread_time_ns, time_ns

from extractor.evidence import EvidenceAdapter


@dataclass
class RecordingMetrics:
    capture_ns: int = 0
    submit_ns: int = 0
    blocked_ns: int = 0
    encode_ns: int = 0
    write_ns: int = 0
    flush_ns: int = 0
    worker_cpu_ns: int = 0
    drain_ns: int = 0
    records: int = 0
    flushes: int = 0
    payload_bytes: int = 0
    framed_bytes: int = 0
    queue_high_water: int = 0


class MeasuredBackend:
    def __init__(self, backend, metrics):
        self.backend, self.metrics, self.name = backend, metrics, backend.name

    def prepare(self, schema):
        codec = self.backend.prepare(schema)
        metrics = self.metrics

        class MeasuredCodec:
            def encode(self, value):
                started = perf_counter_ns()
                result = codec.encode(value)
                metrics.encode_ns += perf_counter_ns() - started
                metrics.payload_bytes += len(result)
                return result

            def decode(self, value):
                return codec.decode(value)

        return MeasuredCodec()


class MeasuredOutput:
    """Times shared compression plus underlying writes; no codec owns this layer."""

    def __init__(self, output, metrics):
        self.output, self.metrics = output, metrics

    def write(self, value):
        started = perf_counter_ns()
        result = self.output.write(value)
        self.metrics.write_ns += perf_counter_ns() - started
        self.metrics.framed_bytes += len(value)
        return result

    def flush(self):
        started = perf_counter_ns()
        self.output.flush()
        self.metrics.flush_ns += perf_counter_ns() - started


_STOP, _FLUSH = object(), object()
_active_recorders = 0
_restore_gc = False


def _producer_collect():
    # CPython may otherwise finalize cyclic Z3 objects on the writer thread
    # while the producer is inside a native solver call. Collect only at the
    # producer's recording boundary, where it is outside native calls.
    counts, limits = gc.get_count(), gc.get_threshold()
    if limits[0] and counts[0] >= limits[0]:
        generation = 2 if counts[2] >= limits[2] else 1 if counts[1] >= limits[1] else 0
        gc.collect(generation)


class BackgroundRecorder:
    """Single producer; submitted values must be immutable semantic snapshots."""

    def __init__(self, *, backend, types, run, output, capacity=64):
        if capacity < 1:
            raise ValueError("recording queue capacity must be positive")
        self.metrics = RecordingMetrics()
        self.adapter = EvidenceAdapter(
            backend=MeasuredBackend(backend, self.metrics),
            types=types,
            run=run,
            output=MeasuredOutput(output, self.metrics),
        )
        self._queue = Queue(maxsize=capacity)
        self._sequence = 0
        self._error = None
        self._closed = False
        self._worker = Thread(target=self._consume, name="evidence-writer", daemon=True)
        global _active_recorders, _restore_gc
        if not _active_recorders:
            _restore_gc = gc.isenabled()
            gc.disable()
        _active_recorders += 1
        self._worker.start()

    def _check(self):
        if self._error is not None:
            raise RuntimeError("background evidence recording failed") from self._error

    def _put(self, item):
        self._check()
        started = perf_counter_ns()
        try:
            self._queue.put_nowait(item)
        except Full:
            blocked = perf_counter_ns()
            while True:
                self._check()
                try:
                    self._queue.put(item, timeout=0.05)
                    break
                except Full:
                    continue
            self.metrics.blocked_ns += perf_counter_ns() - blocked
        self.metrics.submit_ns += perf_counter_ns() - started
        self.metrics.queue_high_water = max(
            self.metrics.queue_high_water, self._queue.qsize()
        )
        self._check()

    def capture(self, factory, *, context=None):
        started = perf_counter_ns()
        value = factory()
        self.metrics.capture_ns += perf_counter_ns() - started
        return self.emit(value, context=context)

    def emit(self, value, *, context=None):
        if self._closed:
            raise ValueError("recorder is closed")
        _producer_collect()
        identifier = f"{self.adapter.stream_id}:{self._sequence}"
        self._put((identifier, time_ns(), context, value))
        self._sequence += 1
        return identifier

    def sample_complete(self):
        if self._closed:
            raise ValueError("recorder is closed")
        self._put(_FLUSH)

    def _consume(self):
        started = thread_time_ns()
        try:
            while True:
                item = self._queue.get()
                if item is _STOP:
                    self.adapter.flush()
                    return
                if item is _FLUSH:
                    self.adapter.flush()
                    self.metrics.flushes += 1
                    continue
                identifier, timestamp, context, value = item
                actual = self.adapter.emit(
                    value, context=context, timestamp_ns=timestamp
                )
                if actual != identifier:
                    raise AssertionError("producer/writer record sequences diverged")
                self.metrics.records += 1
        except (
            BaseException
        ) as error:  # noqa: BLE001  # Re-raise on the producer thread.
            self._error = error
        finally:
            self.metrics.worker_cpu_ns = thread_time_ns() - started

    def close(self):
        if self._closed:
            self._check()
            return
        self._closed = True
        started = perf_counter_ns()
        try:
            self._put(_STOP)
            self._worker.join()
            self._check()
        finally:
            self.metrics.drain_ns = perf_counter_ns() - started
            global _active_recorders
            _active_recorders -= 1
            if not _active_recorders and _restore_gc:
                gc.enable()
