# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Startup, transport, and teardown remain bounded even if a child fails."""

import signal
import subprocess
from unittest.mock import Mock

import pytest
from extractor import fuzz_runner as runner


@pytest.mark.parametrize("seconds", [0, -1])
def test_rejects_nonpositive_budget(seconds):
    with pytest.raises(ValueError, match="positive"):
        runner.run_bounded("", b"", seconds)


@pytest.mark.parametrize(
    "mode",
    [
        "startup",
        "progress",
        "ignore_term",
        "exit",
        "progress_exit",
        "signal_exit",
        "error",
        "complete",
    ],
)
def test_child_failures_and_startup_are_bounded(monkeypatch, mode):
    scripts = {
        "startup": "import time; time.sleep(60)",
        "progress": "connection.send(('progress', {'status': 'mismatch', 'witness': {'rax': 7}})); time.sleep(60)",
        "ignore_term": "signal.signal(signal.SIGTERM, signal.SIG_IGN); connection.send(('progress', {'status': 'incomplete'})); time.sleep(60)",
        "exit": "raise SystemExit(7)",
        "progress_exit": "connection.send(('progress', {'status': 'mismatch', 'witness': {'rax': 11}, 'active_input': {'instruction_hex': '90'}})); raise SystemExit(7)",
        "signal_exit": "import os, resource; resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); connection.send(('progress', {'status': 'mismatch', 'witness': {'rax': 13}, 'active_input': {'instruction_hex': 'c3'}})); os.kill(os.getpid(), signal.SIGABRT)",
        "error": "connection.send(('error', 'synthetic worker error'))",
        "complete": "connection.send(('complete', {'status': 'pass', 'processing': 'complete'}))",
    }
    children = []

    def launch(arguments, **kwargs):
        script = (
            "import sys, time, signal\nfrom multiprocessing.connection import Connection\nconnection = Connection(int(sys.argv[2]), readable=False)\n"
            + scripts[mode]
        )
        child = subprocess.Popen(arguments[:3] + [script] + arguments[4:], **kwargs)
        children.append(child)
        if mode in {"exit", "progress_exit", "signal_exit"}:
            child.wait(timeout=5)
        return child

    monkeypatch.setattr(runner, "Popen", launch)
    # Much larger than a pipe buffer, and never read by the failing children.
    options = dict(examples=1, stage="discover")
    if mode == "startup":
        options["previous"] = {
            "status": "mismatch",
            "witness": {"rax": 9},
            "differences": [],
            "checkpoint": {},
        }
    if mode in {"exit", "progress_exit", "signal_exit", "error"}:
        report = runner.run_bounded("x" * 1_000_000, b"\x90", 2, **options)
        assert report["processing"] == "incomplete"
        if mode == "error":
            assert report["reason"] == "fuzz worker reported an error"
            assert report["error"] == "synthetic worker error"
        else:
            assert report["reason"] == "fuzz worker exited without a result"
            if mode == "signal_exit":
                assert report["worker_exit_code"] == -signal.SIGABRT
                assert report["worker_signal"] == "SIGABRT"
            else:
                assert report["worker_exit_code"] == 7
        if mode == "progress_exit":
            assert report["witness"] == {"rax": 11}
            assert report["active_input"] == {"instruction_hex": "90"}
        if mode == "signal_exit":
            assert report["witness"] == {"rax": 13}
            assert report["active_input"] == {"instruction_hex": "c3"}
    else:
        report = runner.run_bounded("x" * 1_000_000, b"\x90", 0.5, **options)
        assert report["elapsed_seconds"] < 5
        if mode == "complete":
            assert report["status"] == "pass"
        else:
            assert report["processing"] == "incomplete"
            assert report["reason"] == "time budget exhausted"
        if mode == "startup":
            assert report["witness"] == {"rax": 9}
        if mode == "progress":
            assert report["witness"] == {"rax": 7}
    assert len(children) == 1
    assert children[0].poll() is not None


def test_failed_launch_closes_connections(monkeypatch):
    connections = runner.Pipe(duplex=False)
    monkeypatch.setattr(runner, "Pipe", lambda **kwargs: connections)
    monkeypatch.setattr(runner, "Popen", Mock(side_effect=OSError("cannot launch")))
    with pytest.raises(OSError, match="cannot launch"):
        runner.run_bounded("", b"", 1, examples=1, stage="discover")
    assert all(connection.closed for connection in connections)


def test_worker_reports_bootstrap_payload_errors():
    connection = Mock()
    runner._worker(connection, "not JSON", b"", {})
    assert connection.send.call_args.args[0][0] == "error"
    connection.close.assert_called_once()


def test_recorded_worker_ignores_followup_signals_while_draining(monkeypatch):
    from contextlib import contextmanager
    from extractor import evidence_session

    handlers, drained = {}, []
    monkeypatch.setattr(
        runner.signal,
        "signal",
        lambda number, handler: handlers.__setitem__(number, handler),
    )

    @contextmanager
    def recording(options):
        try:
            yield None
        finally:
            assert handlers[runner.signal.SIGINT] == runner.signal.SIG_IGN
            assert handlers[runner.signal.SIGTERM] == runner.signal.SIG_IGN
            drained.append(True)

    monkeypatch.setattr(evidence_session, "recording_session", recording)

    def interrupted_fuzz(*args, **kwargs):
        handlers[runner.signal.SIGINT](runner.signal.SIGINT, None)

    monkeypatch.setattr(runner, "fuzz", interrupted_fuzz)
    connection = Mock()
    runner._worker(
        connection,
        '{"schema":"unavailable"}',
        b"\x90",
        {"recording": {}, "vary_inputs": True},
    )
    assert drained == [True]
    connection.close.assert_called_once()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
