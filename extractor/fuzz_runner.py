# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bound one fuzz action while retaining streamed findings on timeout."""

import json
import os
from multiprocessing import Pipe
from multiprocessing.connection import Connection
from subprocess import Popen, TimeoutExpired
import sys
import signal
from tempfile import TemporaryFile
from time import monotonic
import traceback

from extractor import z3_runtime as _z3_runtime  # noqa: F401
from extractor.artifact import InstructionModel
from extractor.fuzzer import fuzz


def _worker(
    connection: Connection, model: str, instruction: bytes, options: dict
) -> None:
    from extractor.evidence_session import recording_session

    def interrupted(signum, frame):
        # Ctrl-C can reach both parent and child; the parent then sends SIGTERM.
        # A second signal must not interrupt the evidence drain already underway.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt("fuzz worker interrupted")

    recording = options.pop("recording", None)
    if recording is not None:
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
    try:
        with recording_session(recording) as evidence:
            report = fuzz(
                None
                if (options.get("vary_inputs") or options.get("continue_on_findings"))
                and json.loads(model).get("schema") != InstructionModel.schema
                else InstructionModel.from_json(model),
                instruction,
                progress=lambda value: connection.send(("progress", value)),
                evidence=evidence,
                **options,
            )
        connection.send(("complete", report))
    except BaseException:
        connection.send(("error", traceback.format_exc()))
    finally:
        connection.close()


def run_bounded(model: str, instruction: bytes, seconds: float, **options) -> dict:
    if seconds <= 0:
        raise ValueError("time budget must be positive")
    report = {
        "schema": "ixyk.differential_fuzz.v1",
        "status": "incomplete",
        "instruction_hex": instruction.hex(),
        "examples_requested": options["examples"],
        "executions": 0,
        "stage": options["stage"],
        "processing": "incomplete",
    }
    previous = options.get("previous")
    if previous:
        report.update(
            {
                key: previous[key]
                for key in ("status", "witness", "differences", "checkpoint")
            }
        )
    started = monotonic()
    # Keep the potentially large request off the process-startup pipe. Popen
    # returns before Python imports run, so the deadline covers child bootstrap
    # as well as fuzzing. A fresh interpreter preserves native-state isolation.
    with TemporaryFile(mode="w+") as request:
        json.dump(
            {"model": model, "instruction": instruction.hex(), "options": options},
            request,
        )
        request.flush()
        request.seek(0)
        receiver, sender = Pipe(duplex=False)
        try:
            worker = Popen(
                [
                    sys.executable,
                    "-P",
                    "-c",
                    "from extractor.fuzz_runner import _subprocess_worker; _subprocess_worker()",
                    str(request.fileno()),
                    str(sender.fileno()),
                ],
                pass_fds=(request.fileno(), sender.fileno()),
                env=os.environ | {"PYTHONPATH": os.pathsep.join(sys.path)},
            )
        except BaseException:
            receiver.close()
            raise
        finally:
            sender.close()
        worker_failure = None
        try:
            while True:
                remaining = seconds - (monotonic() - started)
                if remaining <= 0 or not receiver.poll(remaining):
                    report["processing"] = "incomplete"
                    report["reason"] = "time budget exhausted"
                    break
                try:
                    kind, value = receiver.recv()
                except EOFError:
                    report["processing"] = "incomplete"
                    report["reason"] = "fuzz worker exited without a result"
                    worker_failure = "exit"
                    break
                if kind == "error":
                    report["processing"] = "incomplete"
                    report["reason"] = "fuzz worker reported an error"
                    report["error"] = value
                    worker_failure = "reported"
                    break
                report = value
                if kind == "complete":
                    break
        finally:
            # Only this call's private child is terminated and reaped.
            if worker.poll() is None:
                if worker_failure is not None:
                    try:
                        worker.wait(timeout=1)
                    except TimeoutExpired:
                        worker.terminate()
                else:
                    worker.terminate()
            try:
                worker.wait(timeout=1)
            except TimeoutExpired:
                worker.kill()
                worker.wait()
            receiver.close()
        if worker_failure is not None:
            report["worker_exit_code"] = worker.returncode
            if (
                worker_failure == "exit"
                and worker.returncode is not None
                and worker.returncode < 0
            ):
                try:
                    report["worker_signal"] = signal.Signals(-worker.returncode).name
                except ValueError:
                    report["worker_signal"] = f"signal {-worker.returncode}"
    report["elapsed_seconds"] = monotonic() - started
    report["budget"] = {"seconds": seconds, "executions": options.get("max_executions")}
    return report


def _subprocess_worker() -> None:
    with os.fdopen(int(sys.argv[1])) as request:
        payload = json.load(request)
    _worker(
        Connection(int(sys.argv[2]), readable=False),
        payload["model"],
        bytes.fromhex(payload["instruction"]),
        payload["options"],
    )
