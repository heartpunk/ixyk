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
    instruction_hex: str


def main(arguments: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--instruction-hex", required=True)
    _ = parser.add_argument("--examples", type=int, default=100)
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    instruction = bytes.fromhex(options.instruction_hex)
    model = extract(load_shellcode(instruction, SOURCE), SOURCE)
    report = fuzz(model, instruction, examples=options.examples)
    assert report["status"] == "pass", report


if __name__ == "__main__":
    main()
