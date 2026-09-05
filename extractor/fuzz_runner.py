# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bound one fuzz action while retaining streamed findings on timeout."""

from multiprocessing import get_context
from multiprocessing.connection import Connection
from time import monotonic
import traceback

from extractor.artifact import InstructionModel
from extractor.fuzzer import fuzz


def _worker(
    connection: Connection, model: str, instruction: bytes, options: dict
) -> None:
    try:
        report = fuzz(
            InstructionModel.from_json(model),
            instruction,
            progress=lambda value: connection.send(("progress", value)),
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
    # A fresh interpreter avoids inheriting native solver/emulator state.
    context = get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    worker = context.Process(target=_worker, args=(sender, model, instruction, options))
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
    worker.start()
    sender.close()
    try:
        while True:
            remaining = seconds - (monotonic() - started)
            if remaining <= 0 or not receiver.poll(remaining):
                report["processing"] = "incomplete"
                report["reason"] = "time budget exhausted"
                break
            try:
                kind, value = receiver.recv()
            except EOFError as error:
                raise RuntimeError("fuzz worker exited without a result") from error
            if kind == "error":
                raise RuntimeError(value)
            report = value
            if kind == "complete":
                break
    finally:
        # Only this action's private worker is terminated, never another job.
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=1)
        if worker.is_alive():
            worker.kill()
            worker.join()
        receiver.close()
    report["elapsed_seconds"] = monotonic() - started
    report["budget"] = {"seconds": seconds, "executions": options.get("max_executions")}
    return report
