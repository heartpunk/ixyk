# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
"""File ownership and CLI options for optional evidence recording."""

from contextlib import contextmanager
from pathlib import Path


def add_recording_arguments(parser):
    parser.add_argument("--recording", choices=("off", "reference-json"), default="off")
    parser.add_argument("--evidence-output", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--invocation-id")


def recording_options(parser, options):
    if options.recording == "off":
        return None
    if not all((options.evidence_output, options.commit, options.invocation_id)):
        parser.error(
            "recording requires --evidence-output, --commit, and --invocation-id"
        )
    return dict(
        path=str(options.evidence_output.resolve()),
        commit=options.commit,
        invocation_id=options.invocation_id,
    )


@contextmanager
def recording_session(options):
    if options is None:
        yield None
        return
    import zstandard
    from extractor.evidence import RunContext
    from extractor.evidence_events import EvidenceHooks, evidence_types
    from extractor.evidence_recording import BackgroundRecorder
    from extractor.evidence_reference_json import ReferenceJSONBackend

    with Path(options["path"]).open("xb") as raw:
        with zstandard.ZstdCompressor(level=3).stream_writer(
            raw, closefd=False
        ) as compressed:
            recorder = BackgroundRecorder(
                backend=ReferenceJSONBackend(),
                types=evidence_types(),
                run=RunContext(options["commit"], options["invocation_id"]),
                output=compressed,
            )
            try:
                yield EvidenceHooks(recorder)
            finally:
                recorder.close()
