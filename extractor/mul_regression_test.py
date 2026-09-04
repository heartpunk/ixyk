# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Replay the first seeded unsigned-MUL differential witness."""

from extractor.amd64_state import FLAG_NAMES, REGISTER_NAMES
from extractor.extractor import extract
from extractor.fuzzer import CompiledModel, ConcreteState, emulate
from extractor.runtime import load_shellcode


SOURCE = 0x400000
INSTRUCTION = bytes.fromhex("48f7e3")  # mul rbx


def main() -> None:
    scalars = {name: 0 for name in REGISTER_NAMES} | {
        "rax": 792792,
        "rbx": 11634037725980,
        "rsp": 0x1000,
        "rip": SOURCE,
    } | {f"rflags_{name}": 0 for name in FLAG_NAMES}
    before = ConcreteState(scalars, dict(enumerate(INSTRUCTION, SOURCE)))
    model = CompiledModel(extract(load_shellcode(INSTRUCTION, SOURCE), SOURCE))
    assert model.differences(before, emulate(INSTRUCTION, before)) == ()


if __name__ == "__main__":
    main()
