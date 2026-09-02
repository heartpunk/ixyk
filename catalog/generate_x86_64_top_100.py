"""Regenerate the common x86-64 instruction-family catalog."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256
import json
from pathlib import Path
from typing import TypedDict, cast
from urllib.request import urlopen


SOURCE = "https://x86instructionpop.com/grouped_data.json"
SOURCE_SHA256 = "f7531052413093997e0bf995801f4284c95e8b7a0807276b66fde1c949c68bcc"
OUTPUT = Path(__file__).with_name("x86_64_top_100.json")


class SourceRow(TypedDict):
    count: int
    mnem: str
    opcode: str
    prefix: str
    size: int
    tag: str


def canonical_name(mnemonic: str) -> str:
    if mnemonic == "MOVABS":
        return "MOV"
    for prefix in ("REPNZ ", "REPZ ", "REP "):
        if mnemonic.startswith(prefix):
            return mnemonic.removeprefix(prefix)
    return mnemonic


def sorted_strings(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def main() -> None:
    with urlopen(SOURCE, timeout=30) as response:
        encoded = response.read()
    digest = sha256(encoded).hexdigest()
    if digest != SOURCE_SHA256:
        raise RuntimeError(f"source digest changed: {digest}")
    source = cast(dict[str, object], json.loads(encoded))
    rows = cast(list[SourceRow], source["instructions"])
    grouped: dict[str, list[SourceRow]] = {}
    for row in rows:
        grouped.setdefault(canonical_name(row["mnem"]), []).append(row)
    ranked = sorted(
        (
            {
                "name": name,
                "occurrences": sum(row["count"] for row in variants),
                "opcode_encodings": sorted_strings(row["opcode"] for row in variants),
                "categories": sorted_strings(row["tag"] for row in variants),
                "source_mnemonics": sorted_strings(row["mnem"] for row in variants),
            }
            for name, variants in grouped.items()
        ),
        key=lambda entry: (-cast(int, entry["occurrences"]), cast(str, entry["name"])),
    )[:100]
    catalog = {
        "schema": "ixyk.x86_64.instruction_catalog.v1",
        "source": {
            "url": SOURCE,
            "sha256": SOURCE_SHA256,
            "corpus": "Ubuntu 16.04 x86-64 ELF binaries from 9,337 packages",
            "retrieved_on": "2026-09-01",
        },
        "aggregation": {
            "identity": "canonical instruction family",
            "score": "sum of occurrence count across every observed variant row",
            "opcode_encodings": (
                "distinct values of the source dataset's opcode field; source rows "
                "are not treated as variants"
            ),
            "normalization": [
                "MOVABS -> MOV",
                "strip REP, REPZ, or REPNZ from source mnemonic into its family",
            ],
            "selection": "first 100 families by score; no feature filtering",
        },
        "instructions": [
            {"rank": rank, **entry} for rank, entry in enumerate(ranked, start=1)
        ],
    }
    OUTPUT.write_text(json.dumps(catalog, indent=2) + "\n")


if __name__ == "__main__":
    main()
