"""Run one permanent extractor-to-emulator semantic regression."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Protocol, cast

from extractor.runtime import load_shellcode

from extractor.extractor import extract
from extractor.fuzzer import fuzz


SOURCE = 0x400000


class _Options(Protocol):
    examples: int
    identity_memory: bool
    skip_fuzz: bool
    instruction_hex: str


def main(arguments: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--instruction-hex", required=True)
    _ = parser.add_argument("--examples", type=int, default=100)
    _ = parser.add_argument("--identity-memory", action="store_true")
    _ = parser.add_argument("--skip-fuzz", action="store_true")
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    instruction = bytes.fromhex(options.instruction_hex)
    model = extract(load_shellcode(instruction, SOURCE), SOURCE)
    if options.identity_memory:
        memory = model.steps[0].simultaneous_update[-1]
        assert memory.name == "mem"
        assert memory.value.op == "var" and memory.value.name == "mem", memory
    if not options.skip_fuzz:
        report = fuzz(model, instruction, examples=options.examples)
        assert report["status"] == "pass", report


if __name__ == "__main__":
    main()
