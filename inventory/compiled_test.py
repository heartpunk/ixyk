# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Progressive compiled fixtures, run by the explicit inventory-smoke output."""

import argparse
import json
from pathlib import Path
import subprocess

from inventory.binary import build_inventory, read_binary
from inventory.golden import load_cache, reachable, report


def run(source: Path, golden: Path, output: Path, cores: int) -> None:
    cache = load_cache(golden)
    results = []
    for size in (1, 8, 64):
        for relocations in (False, True):
            directory = output / f"handlers-{size}-relocs-{int(relocations)}"
            directory.mkdir(parents=True)
            elf = directory / "fixture"
            ir = directory / "fixture.gtirb"
            enabled = int(size > 1)
            subprocess.run(
                [
                    "c++",
                    "-std=c++17",
                    "-O2",
                    "-g",
                    "-march=x86-64",
                    "-fPIE",
                    "-pie",
                    "-fno-builtin-memset",
                    f"-DHANDLERS={size}",
                    f"-DENABLE_FEATURE={enabled}",
                    *(["-Wl,--emit-relocs"] if relocations else []),
                    str(source / "fixture.cc"),
                    str(source / "fixture_helpers.cc"),
                    "-o",
                    str(elf),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "ddisasm",
                    str(elf),
                    "--ir",
                    str(ir),
                    "--with-souffle-relations",
                    "-j",
                    str(cores),
                ],
                check=True,
            )
            handlers = [
                "RETURN",
                "DISABLED",
                "DIRECT",
                "TAIL",
                "BRANCH",
                "RECURSIVE",
                "INDIRECT",
                "EXTERNAL",
                "VECTOR_COPY",
            ]
            handlers += [f"HANDLE<{n}>" for n in range(size)]
            decoder = directory / "decoder"
            decoder.mkdir()
            (decoder / "ia_opcodes.def").write_text(
                "".join(
                    f'bx_define_opcode(OP{n}, "fixture", "fixture", NULL, &BX_CPU_C::{handler}, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)\n'
                    for n, handler in enumerate(handlers)
                )
            )
            inventory = build_inventory(ir, decoder, elf, "fixture")
            nodes, symbols = read_binary(ir, elf)
            rows = {
                target["handlers"][0].removeprefix("BX_CPU_C::"): target
                for target in inventory["targets"]
            }
            failures = []

            def expect(condition, description):
                if not condition:
                    failures.append(description)

            for handler in handlers:
                expect(not rows[handler]["unresolved_handlers"], f"resolve {handler}")
            for handler, dependencies in [
                ("DIRECT", ["nested", "leaf"]),
                ("TAIL", ["leaf"]),
                ("BRANCH", ["branch_entry", "leaf", "nested"]),
                ("RECURSIVE", ["recursive", "leaf"]),
                *[(f"HANDLE<{n}>", ["nested", "leaf"]) for n in range(size)],
            ]:
                addresses, _ = reachable(nodes, rows[handler]["roots"])
                for dependency in dependencies:
                    expect(
                        bool(symbols.get(dependency))
                        and set(symbols[dependency]) <= set(addresses),
                        f"{handler} reaches {dependency}",
                    )
            for handler in ("INDIRECT", "EXTERNAL"):
                _, unknown = reachable(nodes, rows[handler]["roots"])
                expect(bool(unknown), f"{handler} stays unresolved")
            addresses, _ = reachable(nodes, rows["VECTOR_COPY"]["roots"])
            expect(
                any(
                    site["opcode"] == "MOVUPS"
                    for address in addresses
                    for site in nodes[str(address)]["instructions"]
                ),
                "vector bit-copy retained",
            )
            result = report(inventory, cache)
            by_handler = {
                row["handlers"][0].removeprefix("BX_CPU_C::"): row
                for row in result["available"] + result["excluded"]
            }
            expect(
                "trivial_handler_body" in by_handler["RETURN"].get("reasons", []),
                "nop/ret body excluded",
            )
            expect(
                by_handler["DISABLED"].get("trivial_body") == (not enabled),
                "feature-stub distinguished from enabled body",
            )
            (directory / "inventory.json").write_text(
                json.dumps(inventory, sort_keys=True)
            )
            (directory / "report.json").write_text(json.dumps(result, sort_keys=True))
            results.append(
                {
                    "handlers": size,
                    "retained_relocations": relocations,
                    "blocks": len(nodes),
                    "recovered_transfers": sum(
                        len(node.get("recovered_transfers", []))
                        for node in nodes.values()
                    ),
                    "failures": failures,
                }
            )
            print(json.dumps(results[-1]), flush=True)
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if any(result["failures"] for result in results):
        raise AssertionError("compiled fixture failures; see results.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--golden", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cores", type=int, default=1)
    args = parser.parse_args()
    run(args.source, args.golden, args.output, args.cores)
