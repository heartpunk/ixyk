# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Join Bochs decoder entries to Ddisasm's recovered code, without lifting."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split_arguments(text: str) -> list[str]:
    """Split a decoder macro, retaining commas inside template arguments."""
    depth = 0
    quoted = False
    start = 0
    fields = []
    for index, character in enumerate(text):
        if character == '"':
            quoted = not quoted
        if quoted:
            continue
        if character in "(<[":
            depth += 1
        elif character in ")>]":
            depth -= 1
        elif character == "," and depth == 0:
            fields.append(text[start:index].strip())
            start = index + 1
    if depth or quoted:
        raise ValueError(f"unbalanced decoder entry: {text}")
    return fields + [text[start:].strip()]


def decoder_entries(directory: Path) -> list[dict]:
    entries = []
    for path in sorted(directory.glob("ia_opcodes*.def")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = re.match(r"\s*bx_define_opcode\((.*)\)\s*(?://.*)?$", line)
            if not match:
                if re.match(r"\s*bx_define_opcode\(", line):
                    raise ValueError(f"unparsed decoder entry {path}:{number}")
                continue
            fields = split_arguments(match[1])
            if len(fields) != 11:
                raise ValueError(f"unexpected decoder arity at {path}:{number}")
            if fields[1] == '"error"':
                continue
            # These are source-declared forms, not an assertion that the build
            # enables them. Only compiled symbol resolution admits a root.
            for form, handler in (("register", fields[4]), ("memory", fields[3])):
                if handler == "NULL":
                    continue
                roots = [handler.removeprefix("&")]
                # LOAD_* reads the decoded execute2 pointer. Retain both roots
                # but do not silently resolve that indirect call here.
                if form == "memory" and fields[4] != "NULL":
                    roots.append(fields[4].removeprefix("&"))
                entries.append(
                    {
                        "id": f"{fields[0]}:{form}",
                        "mnemonic": json.loads(fields[1]),
                        "form": form,
                        "isa": fields[5],
                        "operands": fields[6:10],
                        "attributes": fields[10],
                        "handlers": sorted(set(roots)),
                        "source": f"{path.name}:{number}",
                    }
                )
    if not entries:
        raise ValueError("no Bochs decoder entries found")
    if len({entry["id"] for entry in entries}) != len(entries):
        raise ValueError("duplicate Bochs form identities")
    return entries


def symbol_key(name: str) -> str:
    """Normalize only the function-pointer template spelling used by Bochs."""
    name = re.sub(r"&\((\w+)\([^()]*\)\)", r"\1", name)
    match = re.search(r"BX_CPU_C::\w+", name)
    if not match:
        return name
    end = match.end()
    if name[end : end + 1] == "<":
        depth = 0
        for index in range(end, len(name)):
            if name[index] == "<":
                depth += 1
            elif name[index] == ">":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        else:
            raise ValueError(f"unbalanced template symbol: {name}")
    return re.sub(r"[ &]", "", name[match.start() : end])


def relation(module, name: str) -> list[list[str]]:
    key = f"disassembly.{name}"
    for table in ("souffleOutputs", "souffleFacts"):
        if table in module.aux_data and key in module.aux_data[table].data:
            _, contents = module.aux_data[table].data[key]
            return [line.split("\t") for line in contents.splitlines()]
    raise ValueError(f"Ddisasm relation {key} missing; use --with-souffle-relations")


def number(text: str) -> int:
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def elf_segments(path: Path) -> list[tuple[int, bytes]]:
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 input")
    offset = struct.unpack_from("<Q", data, 32)[0]
    entry_size, count = struct.unpack_from("<HH", data, 54)
    if entry_size != 56:
        raise ValueError("unexpected ELF program-header size")
    segments = []
    for index in range(count):
        kind, _, file_offset, address, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * entry_size
        )
        if kind == 1:
            segments.append((address, data[file_offset : file_offset + size]))
    return segments


def relative_transfer(site: dict) -> tuple[int, bool] | None:
    """Read x86-64 relative destinations from the already verified ELF bytes.

    Ddisasm can omit edges for linked ELF files retaining static relocations.
    The displacement in the linked instruction is authoritative; symbols and
    relocation symbol-table indices are deliberately not used here.
    """
    code = bytes.fromhex(site["hex"])
    offset = 0
    while offset < len(code) and (
        code[offset] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF2, 0xF3)
        or 0x40 <= code[offset] <= 0x4F
    ):
        offset += 1
    body = code[offset:]
    if not body:
        return None
    opcode = body[0]
    size = 0
    continuation = True
    if opcode in (0xE8, 0xE9):
        size = 4
        continuation = opcode == 0xE8
    elif opcode == 0xEB or 0x70 <= opcode <= 0x7F or 0xE0 <= opcode <= 0xE3:
        size = 1
        continuation = opcode != 0xEB
    elif len(body) >= 2 and body[0] == 0x0F and 0x80 <= body[1] <= 0x8F:
        size = 4
        body = body[1:]
    if not size or len(body) != size + 1:
        return None
    return (
        site["address"] + len(code) + int.from_bytes(body[1:], "little", signed=True),
        continuation,
    )


def audit_transfers(nodes: dict) -> None:
    """Account for transfers independently of the presence of Ddisasm edges.

    Only destinations at recovered block boundaries are admitted. Preserve all
    original unknowns and record each added edge's byte-level provenance.
    Unresolved register/memory transfers always remain unknown, even if the
    graph contains one or more speculative targets.
    """
    for node in nodes.values():
        successors = set(node["successors"])
        unknown = set(node["unknown"])
        recovered = []
        for site in node["instructions"]:
            opcode = site["opcode"]
            transfer = relative_transfer(site)
            if transfer is not None:
                destination, continuation = transfer
                destinations = [(destination, "relative_target")]
                if continuation:
                    destinations.append(
                        (
                            site["address"] + len(bytes.fromhex(site["hex"])),
                            "continuation",
                        )
                    )
                for target, kind in destinations:
                    if str(target) not in nodes:
                        unknown.add("relative_transfer_target_not_recovered")
                    elif target not in successors:
                        successors.add(target)
                        recovered.append(
                            {"address": site["address"], "target": target, "kind": kind}
                        )
            elif opcode.startswith(("CALL", "JMP")):
                unknown.add("indirect_or_unclassified_transfer")
            elif opcode.startswith(("J", "LOOP")):
                unknown.add("unclassified_branch")
            elif opcode in (
                "SYSCALL",
                "SYSENTER",
                "SYSEXIT",
                "SYSRET",
                "INT",
                "INT3",
                "IRET",
                "IRETQ",
                "HLT",
                "UD2",
            ):
                unknown.add("system_effect")
        node["successors"] = sorted(successors)
        node["unknown"] = sorted(unknown)
        node["recovered_transfers"] = recovered


def read_binary(path: Path, elf: Path) -> tuple[dict, dict]:
    import gtirb

    ir = gtirb.IR.load_protobuf(str(path))
    if len(ir.modules) != 1:
        raise ValueError("expected one ELF module per inventory")
    module = ir.modules[0]
    segments = elf_segments(elf)
    if module.isa != gtirb.Module.ISA.X64:
        raise ValueError("inventory requires an x86-64 binary")
    raw_symbols = sorted(module.symbols, key=lambda symbol: symbol.name)
    names = subprocess.run(
        ["c++filt"],
        input="\n".join(symbol.name for symbol in raw_symbols) + "\n",
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    symbols: dict[str, set[int]] = {}
    for symbol, name in zip(raw_symbols, names, strict=True):
        if isinstance(symbol.referent, gtirb.CodeBlock) and not symbol.at_end:
            address = symbol.referent.address
            if address is not None:
                symbols.setdefault(symbol_key(name), set()).add(address)
    instructions = {number(row[0]): row for row in relation(module, "instruction")}
    membership: dict[int, list[int]] = {}
    for ea, block in relation(module, "code_in_refined_block"):
        membership.setdefault(number(block), []).append(number(ea))
    nodes = {}
    for block in module.code_blocks:
        address = block.address
        if address is None:
            raise ValueError("unaddressed code block")
        if not any(
            start <= address
            and address + block.size <= start + len(data)
            and data[address - start : address - start + block.size] == block.contents
            for start, data in segments
        ):
            raise ValueError(
                f"GTIRB code does not match the supplied ELF at {address:#x}"
            )
        sites = []
        cursor = address
        for ea in sorted(membership.get(address, [])):
            row = instructions[ea]
            size = number(row[1])
            if ea != cursor or size <= 0 or ea + size > address + block.size:
                raise ValueError(f"non-contiguous recovered code at {address:#x}")
            sites.append(
                {
                    "address": ea,
                    "hex": block.contents[ea - address : ea - address + size].hex(),
                    "opcode": row[3],
                    "prefix": row[2],
                }
            )
            cursor += size
        if cursor != address + block.size:
            raise ValueError(f"incomplete instruction inventory at {address:#x}")
        successors = set()
        unknown = []
        edges = list(ir.cfg.out_edges(block))
        for edge in edges:
            label = edge.label
            if label is None:
                unknown.append("unlabelled_control_flow")
                continue
            if label.type == gtirb.Edge.Type.Return:
                continue
            if label.type in (gtirb.Edge.Type.Syscall, gtirb.Edge.Type.Sysret):
                unknown.append("system_effect")
            if not label.direct:
                # A resolved target is not evidence of an exhaustive target set.
                unknown.append("indirect_control_flow")
            if (
                isinstance(edge.target, gtirb.CodeBlock)
                and edge.target.address is not None
            ):
                successors.add(edge.target.address)
            else:
                unknown.append("external_or_unknown_target")
        if not edges:
            unknown.append("no_classified_exit")
        nodes[str(address)] = {
            "instructions": sites,
            "successors": sorted(successors),
            "unknown": sorted(set(unknown)),
        }
    audit_transfers(nodes)
    return nodes, {key: sorted(value) for key, value in sorted(symbols.items())}


def build_inventory(gtirb_path: Path, decoder: Path, elf: Path, revision: str) -> dict:
    nodes, symbols = read_binary(gtirb_path, elf)
    targets = decoder_entries(decoder)
    for target in targets:
        roots = []
        unresolved = []
        for handler in target["handlers"]:
            addresses = symbols.get(symbol_key(handler), [])
            if len(addresses) != 1:
                unresolved.append({"handler": handler, "addresses": addresses})
            else:
                roots.extend(addresses)
        target["roots"] = sorted(set(roots))
        target["unresolved_handlers"] = unresolved
    return {
        "schema": "ixyk.bochs_binary_inventory.v1",
        "source_revision": revision,
        "elf_sha256": digest(elf),
        "gtirb_sha256": digest(gtirb_path),
        "decoder_sha256": {
            path.name: digest(path) for path in sorted(decoder.glob("ia_opcodes*.def"))
        },
        "scope": "Bochs source-declared decoder forms; compiled handler presence required",
        "nodes": nodes,
        "targets": targets,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gtirb", type=Path, required=True)
    parser.add_argument("--decoder", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = build_inventory(args.gtirb, args.decoder, args.elf, args.source_revision)
    args.output.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
