"""Evaluate a typed instruction model against concrete machine transitions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

from hypothesis import given, settings, strategies as st

from extractor import z3_boundary as _z3
from extractor.amd64_state import (
    AMD64_FLAG_BIT,
    FLAG_NAMES,
    GPR64,
    MEMORY_NAME,
)
from extractor.artifact import InstructionModel, StepSummary
from extractor.typed_z3 import expr_to_z3, variables_from_declarations
from extractor.unicorn_boundary import (
    Emulator,
    amd64_emulator,
    amd64_register,
    unicorn_constant,
)
import z3


@dataclass(frozen=True)
class ConcreteState:
    scalars: Mapping[str, int]
    memory: Mapping[int, int]


class FuzzReport(TypedDict):
    schema: str
    status: Literal["pass", "mismatch"]
    instruction_hex: str
    examples_requested: int
    executions: int
    differences: NotRequired[list[str]]
    witness: NotRequired[dict[str, int]]


_PAGE_SIZE = 0x1000
_U64 = st.integers(min_value=0, max_value=(1 << 64) - 1)


class _Mismatch(AssertionError):
    def __init__(self, before: ConcreteState, differences: Sequence[str]) -> None:
        super().__init__("; ".join(differences))
        self.before: ConcreteState = before
        self.differences: tuple[str, ...] = tuple(differences)


def emulate(instruction: bytes, before: ConcreteState) -> ConcreteState:
    """Execute exactly one instruction over zero-default sparse memory."""

    emulator, memory, mapped = amd64_emulator(), dict(before.memory), set[int]()

    def map_range(address: int, size: int) -> None:
        first = address & -_PAGE_SIZE
        last = (address + size - 1) & -_PAGE_SIZE
        for page in range(first, last + _PAGE_SIZE, _PAGE_SIZE):
            if page not in mapped:
                emulator.mem_map(page, _PAGE_SIZE)
                mapped.add(page)

    for address in memory:
        map_range(address, 1)
    for address, value in memory.items():
        emulator.mem_write(address, bytes((value,)))

    def map_missing(
        _emulator: Emulator,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> bool:
        map_range(address, size)
        return True

    def record_write(
        _emulator: Emulator,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user_data: object,
    ) -> None:
        for offset in range(size):
            byte = value >> (8 * offset) & 0xFF
            if byte:
                memory[address + offset] = byte
            else:
                _ = memory.pop(address + offset, None)

    _ = emulator.hook_add(
        unicorn_constant("UC_HOOK_MEM_READ_UNMAPPED")
        | unicorn_constant("UC_HOOK_MEM_WRITE_UNMAPPED"),
        map_missing,
    )
    _ = emulator.hook_add(unicorn_constant("UC_HOOK_MEM_WRITE"), record_write)
    for register in (*GPR64, "rip"):
        emulator.reg_write(amd64_register(register), before.scalars[register])
    rflags = 1 << 1
    for name in FLAG_NAMES:
        rflags |= before.scalars[f"rflags_{name}"] << AMD64_FLAG_BIT[name]
    emulator.reg_write(amd64_register("rflags"), rflags)

    source = before.scalars["rip"]
    emulator.emu_start(source, source + len(instruction), count=1)
    scalars = {
        register: emulator.reg_read(amd64_register(register))
        for register in (*GPR64, "rip")
    } | {
        f"rflags_{name}": (
            emulator.reg_read(amd64_register("rflags")) >> AMD64_FLAG_BIT[name]
        )
        & 1
        for name in FLAG_NAMES
    }
    return ConcreteState(scalars, memory)


def fuzz(artifact: InstructionModel, instruction: bytes, examples: int) -> FuzzReport:
    """Shrink the first model/Unicorn disagreement into a structured result."""

    if examples <= 0:
        raise ValueError("examples must be positive")
    compiled, executions = CompiledModel(artifact), 0
    code_memory = dict(enumerate(instruction, artifact.source))

    @settings(
        max_examples=examples,
        derandomize=True,
        deadline=None,
        database=None,
        report_multiple_bugs=False,
    )
    @given(
        registers=st.lists(_U64, min_size=len(GPR64), max_size=len(GPR64)),
        flags=st.lists(
            st.booleans(), min_size=len(FLAG_NAMES), max_size=len(FLAG_NAMES)
        ),
    )
    def agrees(registers: list[int], flags: list[bool]) -> None:
        nonlocal executions
        executions += 1
        scalars = (
            dict(zip(GPR64, registers, strict=True))
            | {"rip": artifact.source}
            | {
                f"rflags_{name}": int(value)
                for name, value in zip(FLAG_NAMES, flags, strict=True)
            }
        )
        before = ConcreteState(scalars, code_memory)
        try:
            after = emulate(instruction, before)
        except Exception as error:
            details = f"emulator {type(error).__name__}: {error}"
            raise _Mismatch(before, (details,)) from error
        differences = compiled.differences(before, after)
        if differences:
            raise _Mismatch(before, differences)

    report: FuzzReport = {
        "schema": "ixyk.differential_fuzz.v1",
        "status": "pass",
        "instruction_hex": instruction.hex(),
        "examples_requested": examples,
        "executions": 0,
    }
    try:
        agrees()
    except _Mismatch as mismatch:
        report["status"] = "mismatch"
        report["differences"] = list(mismatch.differences)
        report["witness"] = dict(mismatch.before.scalars)
    report["executions"] = executions
    return report


@dataclass(frozen=True)
class _CompiledStep:
    source: StepSummary
    guard: z3.BoolRef
    updates: Mapping[str, z3.ExprRef]
    mirrored_pc: z3.BitVecRef


class CompiledModel:
    """One deserialized model compiled once for many concrete witnesses."""

    def __init__(self, artifact: InstructionModel) -> None:
        self.context: z3.Context = z3.Context()
        self.variables: dict[str, z3.ExprRef] = variables_from_declarations(
            artifact.declarations, self.context
        )
        self.steps: tuple[_CompiledStep, ...] = tuple(
            self._compile(step) for step in artifact.steps
        )

    def _compile(self, step: StepSummary) -> _CompiledStep:
        guard = expr_to_z3(step.guard, self.variables, self.context)
        mirrored_pc = expr_to_z3(step.mirrored_pc, self.variables, self.context)
        if not isinstance(guard, z3.BoolRef):
            raise TypeError("instruction guard is not Boolean")
        if not isinstance(mirrored_pc, z3.BitVecRef):
            raise TypeError("mirrored PC is not a bit-vector")
        return _CompiledStep(
            step,
            guard,
            {
                assignment.name: expr_to_z3(
                    assignment.value, self.variables, self.context
                )
                for assignment in step.simultaneous_update
            },
            mirrored_pc,
        )

    def differences(
        self, before: ConcreteState, after: ConcreteState
    ) -> tuple[str, ...]:
        constraints = self._input_constraints(before)
        enabled = tuple(
            step
            for step in self.steps
            if _z3.check_status(self._check((*constraints, step.guard))) == z3.Z3_L_TRUE
        )
        if len(enabled) != 1:
            return (f"enabled edges: {len(enabled)}; expected exactly one",)

        step = enabled[0]
        solver = self._solver((*constraints, step.guard))
        _z3.require_sat(_z3.solver_check(solver))
        solution = _z3.solver_model(solver)
        differences = [
            f"{name}: model={actual:#x}, emulator={expected:#x}"
            for name, expected in after.scalars.items()
            if name != MEMORY_NAME
            and (actual := self._evaluate_bv(solution, step.updates[name])) != expected
        ]
        mirrored_pc = self._evaluate_bv(solution, step.mirrored_pc)
        if mirrored_pc != after.scalars["rip"]:
            differences.append(
                f"mirrored_pc: model={mirrored_pc:#x}, emulator="
                + f"{after.scalars['rip']:#x}"
            )
        if self._memory_differs(
            (*constraints, step.guard), step.updates[MEMORY_NAME], after.memory
        ):
            differences.append("memory differs")
        return tuple(differences)

    def _input_constraints(self, state: ConcreteState) -> tuple[z3.BoolRef, ...]:
        constraints: list[z3.BoolRef] = []
        for name, value in state.scalars.items():
            variable = self.variables[name]
            if not isinstance(variable, z3.BitVecRef):
                raise TypeError(f"input {name!r} is not a bit-vector")
            constraints.append(
                _z3.equal(
                    variable,
                    _z3.bit_vec_val(value, variable.size(), self.context),
                )
            )
        memory = self.variables[MEMORY_NAME]
        if not isinstance(memory, z3.ArrayRef):
            raise TypeError("input memory is not an array")
        constraints.append(_z3.equal(memory, self._memory(state.memory)))
        return tuple(constraints)

    def _memory(self, values: Mapping[int, int]) -> z3.ArrayRef:
        result = _z3.constant_array(
            _z3.bit_vec_sort(64, self.context),
            _z3.bit_vec_val(0, 8, self.context),
        )
        for address, value in sorted(values.items()):
            if not 0 <= address < 1 << 64 or not 0 <= value < 1 << 8:
                raise ValueError("concrete memory is not a BV64-to-BV8 map")
            result = _z3.store(
                result,
                _z3.bit_vec_val(address, 64, self.context),
                _z3.bit_vec_val(value, 8, self.context),
            )
        return result

    def _memory_differs(
        self,
        constraints: Sequence[z3.BoolRef],
        modeled: z3.ExprRef,
        expected: Mapping[int, int],
    ) -> bool:
        if not isinstance(modeled, z3.ArrayRef):
            raise TypeError("output memory is not an array")
        result = self._check(
            (*constraints, _z3.negate(_z3.equal(modeled, self._memory(expected))))
        )
        status = _z3.check_status(result)
        if status == z3.Z3_L_UNDEF:
            raise AssertionError("Z3 returned unknown while comparing memory")
        return status == z3.Z3_L_TRUE

    def _solver(self, constraints: Sequence[z3.BoolRef]) -> z3.Solver:
        solver = _z3.solver(self.context)
        for constraint in constraints:
            _z3.solver_add(solver, constraint)
        return solver

    def _check(self, constraints: Sequence[z3.BoolRef]) -> z3.CheckSatResult:
        return _z3.solver_check(self._solver(constraints))

    @staticmethod
    def _evaluate_bv(model: z3.ModelRef, expression: z3.ExprRef) -> int:
        value = _z3.model_eval(model, expression)
        if not isinstance(value, z3.BitVecNumRef):
            raise TypeError("modeled scalar output is not concrete")
        return value.as_long()
