# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""The same four-opcode fuzz workload with recording off or a selected codec."""

import argparse
from dataclasses import asdict
import importlib
import json
from pathlib import Path
import resource
import sys
from time import perf_counter_ns

from extractor.evidence import RunContext
from extractor.evidence_events import EvidenceHooks, evidence_types
from extractor.evidence_recording import BackgroundRecorder


CASES = (
    ("ADD", "4801d8"),
    ("JE", "7400"),
    ("LEA", "488d444b08"),
    ("MOVSD", "f20f10c1"),
)


def _fuzz(*args, **kwargs):
    # Imports the native runtime only when actually executing the workload.
    from extractor import z3_runtime  # noqa: F401  # preload before Z3 import
    from extractor.fuzzer import fuzz

    return fuzz(*args, **kwargs)


def _backend(options):
    if options.recording == "off":
        return None
    if options.recording == "reference-json":
        from extractor.evidence_reference_json import ReferenceJSONBackend

        return ReferenceJSONBackend()
    module, name = options.backend.split(":", 1)
    return getattr(importlib.import_module(module), name)()


class _RawOutput:
    def __init__(self, output):
        self.output, self.io_ns = output, 0

    def write(self, data):
        started = perf_counter_ns()
        result = self.output.write(data)
        self.io_ns += perf_counter_ns() - started
        return result

    def flush(self):
        started = perf_counter_ns()
        self.output.flush()
        self.io_ns += perf_counter_ns() - started


def run(options):
    options.output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    started = perf_counter_ns()
    for opcode, hexcode in CASES:
        if options.opcode and opcode not in options.opcode:
            continue
        case_started = perf_counter_ns()
        recorder, hooks, raw, compressed, measured = None, None, None, None, None
        path = options.output_dir / f"{opcode}.evidence.zst"
        finalize_ns = 0
        try:
            backend = _backend(options)
            if backend is not None:
                import zstandard

                raw = path.open("xb")
                measured = _RawOutput(raw)
                compressed = zstandard.ZstdCompressor(level=3).stream_writer(
                    measured, closefd=False
                )
                recorder = BackgroundRecorder(
                    backend=backend,
                    types=evidence_types(),
                    run=RunContext(options.commit, options.invocation_id),
                    output=compressed,
                    capacity=options.queue_capacity,
                )
                hooks = EvidenceHooks(recorder)
            setup_ns = perf_counter_ns() - case_started
            compute_started = perf_counter_ns()
            report = _fuzz(
                None,
                bytes.fromhex(hexcode),
                options.samples,
                stage="discover",
                vary_inputs=True,
                continue_on_findings=True,
                evidence=hooks,
                max_executions=options.samples,
            )
            compute_ns = perf_counter_ns() - compute_started
        finally:
            try:
                if recorder is not None:
                    recorder.close()
            finally:
                finalized = perf_counter_ns()
                try:
                    if compressed is not None:
                        compressed.close()
                finally:
                    if raw is not None:
                        raw.close()
                    finalize_ns = perf_counter_ns() - finalized
        report.update(
            opcode=opcode,
            setup_ns=setup_ns,
            compute_ns=compute_ns,
            elapsed_ns=perf_counter_ns() - case_started,
            finalize_ns=finalize_ns,
            recording=asdict(recorder.metrics) if recorder is not None else None,
            io_ns=measured.io_ns if measured is not None else 0,
            output_bytes=path.stat().st_size if recorder is not None else 0,
        )
        reports.append(report)
        print(f"{opcode}: {report['executions']}/{options.samples} samples", flush=True)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result = {
        "schema": "ixyk.evidence_benchmark.v1",
        "commit": options.commit,
        "invocation_id": options.invocation_id,
        "recording": options.recording,
        "backend": options.backend,
        "samples_per_opcode": options.samples,
        "queue_capacity": options.queue_capacity,
        "compression": "zstd:3",
        "elapsed_ns": perf_counter_ns() - started,
        "peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
        "cases": reports,
    }
    (options.output_dir / "benchmark.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--recording", choices=("off", "reference-json", "backend"), default="off"
    )
    parser.add_argument("--backend", help="module:Class for a codec under evaluation")
    parser.add_argument(
        "--commit", required=True, help="exact source commit of this run"
    )
    parser.add_argument("--invocation-id", required=True, help="Bazel invocation UUID")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--opcode", action="append", choices=[name for name, _ in CASES]
    )
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--queue-capacity", type=int, default=64)
    options = parser.parse_args(arguments)
    if options.samples < 1 or options.queue_capacity < 1:
        parser.error("samples and queue capacity must be positive")
    if (options.recording == "backend") != bool(options.backend):
        parser.error("--backend is required exactly when --recording=backend")
    if options.backend and (
        options.backend.count(":") != 1 or not all(options.backend.split(":"))
    ):
        parser.error("--backend must have the form module:Class")
    return run(options)


if __name__ == "__main__":
    main()
