"""Extract ADD once, then differentially fuzz its typed model."""

from extractor.runtime import load_shellcode

from collections.abc import Mapping

from hypothesis import given, settings, strategies as st

from extractor import z3_boundary as _z3
from extractor.amd64_state import AMD64_FLAG_BIT, FLAG_NAMES, GPR64, MEMORY_NAME
from extractor.artifact import InstructionModel
from extractor.extractor import extract
from extractor.typed_z3 import expr_to_z3, variables_from_declarations
from extractor.unicorn_boundary import amd64_emulator, amd64_register
import z3


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")
PAGE = SOURCE & ~0xFFF
PAGE_SIZE = 0x1000
U64 = st.integers(min_value=0, max_value=(1 << 64) - 1)


class CompiledModel:
    """One deserialized instruction model compiled once for many witnesses."""

    def __init__(self, artifact: InstructionModel) -> None:
        if len(artifact.steps) != 1:
            raise AssertionError(f"expected one ADD step, got {len(artifact.steps)}")
        self.context: z3.Context = z3.Context()
        self.variables: dict[str, z3.ExprRef] = variables_from_declarations(
            artifact.declarations, self.context
        )
        step = artifact.steps[0]
        self.guard: z3.ExprRef = expr_to_z3(step.guard, self.variables, self.context)
        self.outputs: dict[str, z3.ExprRef] = {
            assignment.name: expr_to_z3(assignment.value, self.variables, self.context)
            for assignment in step.simultaneous_update
            if assignment.name != MEMORY_NAME
        }

    def evaluate(self, inputs: Mapping[str, int]) -> dict[str, int]:
        solver = _z3.solver(self.context)
        for name, value in inputs.items():
            variable = self.variables[name]
            if not isinstance(variable, z3.BitVecRef):
                raise AssertionError(f"input {name!r} is not a bit-vector")
            _z3.solver_add(
                solver,
                _z3.equal(
                    variable,
                    _z3.bit_vec_val(value, variable.size(), self.context),
                ),
            )
        if not isinstance(self.guard, z3.BoolRef):
            raise AssertionError("instruction guard is not Boolean")
        _z3.solver_add(solver, self.guard)
        _z3.require_sat(_z3.solver_check(solver))
        solution = _z3.solver_model(solver)
        result: dict[str, int] = {}
        for name, expression in self.outputs.items():
            value = _z3.model_eval(solution, expression)
            if not isinstance(value, z3.BitVecNumRef):
                raise AssertionError(f"output {name!r} is not concrete")
            result[name] = value.as_long()
        return result


def _inputs(registers: list[int], flags: list[bool]) -> dict[str, int]:
    return (
        dict(zip(GPR64, registers, strict=True))
        | {"rip": SOURCE}
        | {
            f"rflags_{name}": int(value)
            for name, value in zip(FLAG_NAMES, flags, strict=True)
        }
    )


def _unicorn_step(inputs: Mapping[str, int]) -> tuple[dict[str, int], bool]:
    emulator = amd64_emulator()
    emulator.mem_map(PAGE, PAGE_SIZE)
    emulator.mem_write(SOURCE, ADD_RAX_RBX)
    for register in (*GPR64, "rip"):
        emulator.reg_write(amd64_register(register), inputs[register])
    rflags = 1 << 1
    for name in FLAG_NAMES:
        rflags |= inputs[f"rflags_{name}"] << AMD64_FLAG_BIT[name]
    emulator.reg_write(amd64_register("rflags"), rflags)
    before = bytes(emulator.mem_read(PAGE, PAGE_SIZE))
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
    return outputs, bytes(emulator.mem_read(PAGE, PAGE_SIZE)) == before


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
        actual, memory_unchanged = _unicorn_step(inputs)
        assert actual == compiled.evaluate(inputs)
        assert memory_unchanged

    agrees()
    print(encoded)


if __name__ == "__main__":
    main()
