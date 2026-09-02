"""Extract ADD once, then differentially fuzz its typed model."""

from extractor.runtime import load_shellcode

from collections.abc import Mapping

from hypothesis import given, settings, strategies as st

from extractor.amd64_state import AMD64_FLAG_BIT, FLAG_NAMES, GPR64
from extractor.artifact import InstructionModel
from extractor.extractor import extract
from extractor.fuzzer import CompiledModel, ConcreteState
from extractor.unicorn_boundary import amd64_emulator, amd64_register


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")
PAGE = SOURCE & ~0xFFF
PAGE_SIZE = 0x1000
U64 = st.integers(min_value=0, max_value=(1 << 64) - 1)


def _inputs(registers: list[int], flags: list[bool]) -> dict[str, int]:
    return (
        dict(zip(GPR64, registers, strict=True))
        | {"rip": SOURCE}
        | {
            f"rflags_{name}": int(value)
            for name, value in zip(FLAG_NAMES, flags, strict=True)
        }
    )


def _unicorn_step(inputs: Mapping[str, int]) -> ConcreteState:
    emulator = amd64_emulator()
    emulator.mem_map(PAGE, PAGE_SIZE)
    emulator.mem_write(SOURCE, ADD_RAX_RBX)
    for register in (*GPR64, "rip"):
        emulator.reg_write(amd64_register(register), inputs[register])
    rflags = 1 << 1
    for name in FLAG_NAMES:
        rflags |= inputs[f"rflags_{name}"] << AMD64_FLAG_BIT[name]
    emulator.reg_write(amd64_register("rflags"), rflags)
    emulator.emu_start(SOURCE, SOURCE + len(ADD_RAX_RBX), count=1)
    outputs = {
        register: emulator.reg_read(amd64_register(register))
        for register in (*GPR64, "rip")
    } | {
        f"rflags_{name}": (
            emulator.reg_read(amd64_register("rflags")) >> AMD64_FLAG_BIT[name]
        )
        & 1
        for name in FLAG_NAMES
    }
    return ConcreteState(outputs, dict(enumerate(ADD_RAX_RBX, SOURCE)))


def main() -> None:
    extracted = extract(load_shellcode(ADD_RAX_RBX, SOURCE), SOURCE)
    encoded = extracted.to_json()
    model = InstructionModel.from_json(encoded)
    compiled = CompiledModel(model)

    @settings(max_examples=100, derandomize=True, deadline=None, database=None)
    @given(
        registers=st.lists(U64, min_size=len(GPR64), max_size=len(GPR64)),
        flags=st.lists(
            st.booleans(), min_size=len(FLAG_NAMES), max_size=len(FLAG_NAMES)
        ),
    )
    def agrees(registers: list[int], flags: list[bool]) -> None:
        inputs = _inputs(registers, flags)
        before = ConcreteState(inputs, dict(enumerate(ADD_RAX_RBX, SOURCE)))
        assert not compiled.differences(before, _unicorn_step(inputs))

    agrees()
    print(encoded)


if __name__ == "__main__":
    main()
