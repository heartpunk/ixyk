"""Extract ADD once, then differentially fuzz its typed model."""

from extractor.runtime import load_shellcode

from hypothesis import given, settings, strategies as st

from extractor.amd64_state import FLAG_NAMES, GPR64
from extractor.artifact import InstructionModel
from extractor.extractor import extract
from extractor.fuzzer import CompiledModel, ConcreteState, emulate


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")
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
        assert not compiled.differences(before, emulate(ADD_RAX_RBX, before))

    agrees()
    print(encoded)


if __name__ == "__main__":
    main()
