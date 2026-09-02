"""File-producing command line boundary for one instruction extraction."""

# Native runtime must preload declared libstdc++ before Z3 or Angr imports.
from extractor.runtime import load_shellcode

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, cast

from extractor.extractor import extract


DEFAULT_SOURCE = 0x400000


class _Options(Protocol):
    instruction_hex: str
    output: Path
    source: int


def _source(value: str) -> int:
    source = int(value, 0)
    if not 0 <= source < 1 << 64:
        raise argparse.ArgumentTypeError("source must be an unsigned 64-bit address")
    return source


def main(arguments: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--instruction-hex", required=True)
    _ = parser.add_argument("--output", required=True, type=Path)
    _ = parser.add_argument("--source", default=DEFAULT_SOURCE, type=_source)
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    try:
        instruction = bytes.fromhex(options.instruction_hex)
    except ValueError as error:
        parser.error(str(error))
    if not instruction:
        parser.error("instruction must contain at least one byte")
    model = extract(load_shellcode(instruction, options.source), options.source)
    _ = options.output.write_text(model.to_json() + "\n", encoding="utf-8")
