# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Evaluate a typed instruction model against concrete machine transitions."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict
import hashlib
import json
from time import perf_counter

import hypothesis
from hypothesis.database import ExampleDatabase

from hypothesis import Phase, given, seed, settings, strategies as st

from extractor.amd64_state import (
    AMD64_FLAG_BIT,
    FLAG_NAMES,
    GPR64,
    MEMORY_NAME,
    YMM256,
)
from extractor.artifact import InstructionModel
from extractor.concrete_eval import ConcreteArray, evaluator, share_expressions
from extractor.unicorn_boundary import (
    Emulator,
    amd64_emulator,
    amd64_register,
    is_cpu_exception,
    unicorn_constant,
)


@dataclass(frozen=True)
class ConcreteState:
    scalars: Mapping[str, int]
    memory: Mapping[int, int]


class FuzzReport(TypedDict):
    schema: str
    status: Literal["pass", "mismatch", "incomplete", "acquisition_error"]
    error: NotRequired[str]
    input: NotRequired[dict]
    instruction_hex: str
    examples_requested: int
    executions: int
    differences: NotRequired[list[str]]
    witness: NotRequired[dict[str, int]]
    stage: NotRequired[str]
    processing: NotRequired[str]
    reason: NotRequired[str]
    checkpoint: NotRequired[dict]
    explanation: NotRequired[list[str]]
    agreements: NotRequired[int]
    disagreements: NotRequired[int]
    unusable: NotRequired[int]
    acquisition_findings: NotRequired[int]
    generation_findings: NotRequired[int]
    fallback_allocations: NotRequired[dict[str, int]]
    input_sha256: NotRequired[str]
    active_input: NotRequired[dict]
    preparation_seconds: NotRequired[float]
    execution_seconds: NotRequired[float]
    total_seconds: NotRequired[float]
    prepared_models: NotRequired[list[dict]]
    planned_fallback_allocations: NotRequired[dict[str, int]]
    worker_exit_code: NotRequired[int]
    worker_signal: NotRequired[str]


_PAGE_SIZE = 0x1000
_U64 = st.integers(min_value=0, max_value=(1 << 64) - 1)
_U256 = st.integers(min_value=0, max_value=(1 << 256) - 1)
_STACK_POINTER = st.integers(
    min_value=_PAGE_SIZE,
    max_value=(1 << 47) - _PAGE_SIZE,
)
_FUZZED_REGISTERS = GPR64 + YMM256
_REGISTERS = st.tuples(
    *(
        _STACK_POINTER if name == "rsp" else _U256 if name in YMM256 else _U64
        for name in _FUZZED_REGISTERS
    )
)


class _Mismatch(AssertionError):
    def __init__(self, before: ConcreteState, differences: Sequence[str]) -> None:
        super().__init__("; ".join(differences))
        self.before: ConcreteState = before
        self.differences: tuple[str, ...] = tuple(differences)


def emulate(instruction: bytes, before: ConcreteState) -> ConcreteState:
    """Execute exactly one instruction over zero-default sparse memory."""

    emulator, memory, mapped = amd64_emulator(), dict(before.memory), set[int]()

    def map_range(address: int, size: int) -> None:
        address %= 1 << 64
        if address + size > 1 << 64:
            first_size = (1 << 64) - address
            map_range(address, first_size)
            map_range(0, size - first_size)
            return
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
            target = (address + offset) % (1 << 64)
            if byte:
                memory[target] = byte
            else:
                _ = memory.pop(target, None)

    _ = emulator.hook_add(
        unicorn_constant("UC_HOOK_MEM_READ_UNMAPPED")
        | unicorn_constant("UC_HOOK_MEM_WRITE_UNMAPPED")
        | unicorn_constant("UC_HOOK_MEM_FETCH_UNMAPPED"),
        map_missing,
    )
    _ = emulator.hook_add(unicorn_constant("UC_HOOK_MEM_WRITE"), record_write)
    for register in (*_FUZZED_REGISTERS, "rip"):
        emulator.reg_write(amd64_register(register), before.scalars[register])
    rflags = 1 << 1
    for name in FLAG_NAMES:
        rflags |= before.scalars[f"rflags_{name}"] << AMD64_FLAG_BIT[name]
    emulator.reg_write(amd64_register("rflags"), rflags)

    source = before.scalars["rip"]
    emulator.emu_start(source, source + len(instruction), count=1)
    scalars = {
        register: emulator.reg_read(amd64_register(register))
        for register in (*_FUZZED_REGISTERS, "rip")
    } | {
        f"rflags_{name}": (
            emulator.reg_read(amd64_register("rflags")) >> AMD64_FLAG_BIT[name]
        )
        & 1
        for name in FLAG_NAMES
    }
    return ConcreteState(scalars, memory)


class ComparisonUnavailable(Exception):
    """The current model cannot establish a unique comparison outcome."""


class _InputAcquisitionError(Exception):
    pass


class _ExecutionBudget(BaseException):
    """Stop Hypothesis without turning resource exhaustion into a test failure."""


class _ReplayDatabase(ExampleDatabase):
    def __init__(self, entries: dict[str, list[str]], *, resume: bool) -> None:
        super().__init__()
        self.entries = {
            bytes.fromhex(key): {bytes.fromhex(value) for value in values}
            for key, values in entries.items()
        }
        self.resume = resume
        self.changed: Callable[[], None] = lambda: None

    def fetch(self, key: bytes) -> Iterable[bytes]:
        values = set(self.entries.get(key, ()))
        if self.resume:
            # Hypothesis 6.160 treats primary-corpus hits as already minimized,
            # skipping shrink AND explain. Resume through its secondary corpus.
            # This suffix is version-sensitive; checkpoint identity pins the
            # Hypothesis version and the stage test exercises actual reduction.
            if key.endswith(b".secondary"):
                values.update(self.entries.get(key.removesuffix(b".secondary"), ()))
            elif not key.endswith(b".pareto"):
                return ()
        return sorted(values)

    def save(self, key: bytes, value: bytes) -> None:
        self.entries.setdefault(key, set()).add(value)
        self.changed()

    def delete(self, key: bytes, value: bytes) -> None:
        self.entries.get(key, set()).discard(value)
        self.changed()

    def export(self) -> dict[str, list[str]]:
        return {
            key.hex(): [value.hex() for value in sorted(values)]
            for key, values in sorted(self.entries.items())
            if values
        }


@dataclass(frozen=True)
class InputLayout:
    base: str
    index: str
    scale: int
    displacement: int

    @classmethod
    def prepare(cls, code):
        from extractor.xed import decode

        return cls.from_decoded(decode(code))

    @classmethod
    def from_decoded(cls, decoded):
        return cls(
            decoded["base"]["name"].lower(),
            decoded["index"]["name"].lower(),
            decoded["scale"],
            decoded["displacement"],
        )


def _input_state(
    code, source, memory, data, registers, flags, vary_inputs, *, layout=None
):
    # Older callers supply only the six arithmetic flags; extra modeled flags
    # default to zero. Production generation supplies the complete flag state.
    if len(flags) == 6:
        flags = [*flags, 0, 0, 0]
    scalars = (
        dict(zip(_FUZZED_REGISTERS, registers, strict=True))
        | {"rip": source}
        | {
            f"rflags_{name}": int(value)
            for name, value in zip(FLAG_NAMES, flags, strict=True)
        }
    )
    memory = dict(memory)
    if vary_inputs:
        # Exercise loads from generated register addresses, including RSP.
        if layout is None:
            layout = InputLayout.prepare(code)
        for address in registers[: len(GPR64)]:
            memory[address] = data
        base = (
            (source + len(code))
            if layout.base in {"rip", "eip"}
            else scalars.get(layout.base, 0)
        )
        if layout.base == "eip":
            base &= (1 << 32) - 1
        index = scalars.get(layout.index, 0)
        address = (base + index * layout.scale + layout.displacement) % (1 << 64)
        memory[address] = data
    initial = {
        (address + i) % (1 << 64): byte
        for address, block in memory.items()
        for i, byte in enumerate(block)
    }
    initial.update({(source + i) % (1 << 64): byte for i, byte in enumerate(code)})
    return ConcreteState(scalars, initial)


def fuzz(
    artifact: InstructionModel | None,
    instruction: bytes,
    examples: int,
    *,
    stage: Literal["discover", "shrink", "explain"] = "discover",
    previous: dict | None = None,
    max_executions: int | None = None,
    progress: Callable[[dict], None] | None = None,
    vary_inputs: bool = False,
    continue_on_findings: bool = False,
    evidence=None,
    acquisition: dict | None = None,
) -> FuzzReport:
    """Discover or resume a failure, exporting an action-local replay database."""
    if examples <= 0 or (max_executions is not None and max_executions <= 0):
        raise ValueError("example and execution budgets must be positive")
    from extractor.fuzz_inputs import MEMORY

    started = perf_counter()

    if artifact is None and not vary_inputs and not continue_on_findings:
        raise ValueError("fixed-input fuzzing requires an available model")
    campaign = None
    if continue_on_findings:
        if stage != "discover":
            raise ValueError("cumulative fuzzing requires discovery")
        from extractor.fuzz_campaign import Campaign

        campaign = Campaign(instruction, evidence, fixed_model=artifact)
    elif evidence is not None:
        raise ValueError("evidence recording requires cumulative fuzzing")
    if campaign is not None:
        campaign.prepare(acquisition=acquisition, vary_encodings=vary_inputs)
    elif artifact is None:
        raise ValueError("fuzzing requires a prepared model")
    codes = st.data() if campaign is not None and vary_inputs else st.just(instruction)
    source = artifact.source if artifact is not None else 0x400000
    layout = (
        InputLayout.prepare(instruction) if vary_inputs and campaign is None else None
    )
    phases = {
        "discover": (Phase.generate,),
        "shrink": (Phase.reuse, Phase.shrink),
        "explain": (Phase.reuse, Phase.shrink, Phase.explain),
    }
    identity = {
        "hypothesis": hypothesis.__version__,
        "strategy": "ixyk.prepared-constructors-source-memory.v2"
        if vary_inputs
        else "ixyk.amd64-registers-flags.v1",
        "model_sha256": hashlib.sha256(artifact.to_json().encode()).hexdigest()
        if artifact
        else None,
        "instruction_hex": instruction.hex(),
    }
    prepared_models = (
        [
            {
                "instruction_hex": item.code.hex(),
                "source": item.source,
                "route": item.route,
                "case_sha256": hashlib.sha256(
                    json.dumps(item.case.to_data(), sort_keys=True).encode()
                ).hexdigest()
                if item.case is not None
                else None,
                "model_sha256": hashlib.sha256(
                    item.compiled.artifact.to_json().encode()
                ).hexdigest(),
            }
            for item in campaign.models
        ]
        if campaign is not None
        else []
    )
    if campaign is not None:
        identity["prepared_models"] = prepared_models
    entries = {}
    if stage != "discover":
        if previous is None or previous.get("status") != "mismatch":
            raise ValueError("failure processing requires a mismatch report")
        checkpoint = previous.get("checkpoint", {})
        if checkpoint.get("identity") != identity:
            raise ValueError(
                "checkpoint model, instruction, strategy or Hypothesis version differs"
            )
        entries = checkpoint.get("entries", {})
        if not entries:
            raise ValueError("checkpoint has no resumable Hypothesis examples")
    elif previous is not None:
        raise ValueError("discovery does not consume a previous report")
    database = _ReplayDatabase(entries, resume=stage != "discover")
    executions, reproduced = 0, False
    report: FuzzReport = {
        "schema": "ixyk.differential_fuzz.v1",
        "status": "incomplete",
        "instruction_hex": instruction.hex(),
        "examples_requested": examples,
        "executions": 0,
        "stage": stage,
        "processing": "incomplete",
    }
    if previous:
        report["status"] = "mismatch"
        report["witness"] = previous["witness"]
        report["differences"] = previous["differences"]

    def publish() -> None:
        report["executions"] = executions
        report["checkpoint"] = {"identity": identity, "entries": database.export()}
        if progress:
            progress(dict(report))

    database.changed = publish
    publish()
    compiled = (
        CompiledModel(artifact) if artifact is not None and campaign is None else None
    )
    preparation_seconds = perf_counter() - started
    sampling_started = perf_counter()
    if campaign is not None:
        report["prepared_models"] = prepared_models
        budget = (
            min(examples, max_executions) if max_executions is not None else examples
        )
        report["planned_fallback_allocations"] = {
            f"{item.code.hex()}@{item.source:x}": (
                budget // len(campaign.models) + (index < budget % len(campaign.models))
            )
            for index, item in enumerate(campaign.models)
            if item.route == "fallback"
        }
        if not campaign.models:
            report.update(
                campaign.summary(),
                reason="preparation produced no executable models",
                preparation_seconds=preparation_seconds,
                execution_seconds=0.0,
                total_seconds=perf_counter() - started,
            )
            publish()
            return report
    sample_input = {}

    def run_case(case_index, case_budget):
        # Keep one structural strategy fixed for each Hypothesis engine. The
        # campaign budget is divided evenly, without changing draws on replay.
        # settings must wrap seed: seed itself disables the database. Keep a fixed
        # seed while explicitly restoring our declared, action-local replay input.
        @settings(
            max_examples=case_budget,
            deadline=None,
            database=database,
            phases=phases[stage],
            report_multiple_bugs=False,
        )
        @seed(0)
        @given(
            code=codes,
            source=st.integers(0, (1 << 64) - 16)
            if campaign is not None and vary_inputs
            else st.just(source),
            memory=MEMORY if vary_inputs else st.just({}),
            data=st.binary(min_size=32, max_size=32) if vary_inputs else st.just(b""),
            registers=st.tuples(
                *(_U256 if name in YMM256 else _U64 for name in _FUZZED_REGISTERS)
            )
            if vary_inputs
            else _REGISTERS,
            flags=st.lists(
                st.booleans(), min_size=len(FLAG_NAMES), max_size=len(FLAG_NAMES)
            ),
        )
        def agrees(
            code: bytes,
            source: int,
            memory: dict[int, bytes],
            data: bytes,
            registers: tuple[int, ...],
            flags: list[bool],
        ) -> None:
            nonlocal executions, reproduced, sample_input
            if max_executions is not None and executions >= max_executions:
                raise _ExecutionBudget()
            selected = campaign.select(case_index + 1) if campaign is not None else None
            if selected is not None:
                if vary_inputs:
                    selected = campaign.bind(selected, code, source)
                code, source = selected.code, selected.source
            executions += 1
            before = _input_state(
                code,
                source,
                memory,
                data,
                registers,
                flags,
                vary_inputs,
                layout=selected.layout if selected is not None else layout,
            )
            if campaign is not None:
                report["active_input"] = {
                    "instruction_hex": code.hex(),
                    "source": source,
                    "scalars": dict(before.scalars),
                    "memory": {str(k): v for k, v in sorted(before.memory.items())},
                }
            publish()
            if campaign is not None:
                assert selected is not None
                campaign.compare(selected.compiled, code, before, executions)
                report.pop("active_input", None)
                report.update(campaign.summary())
                publish()
                return
            scalars, initial = before.scalars, before.memory
            sample_input = {
                "instruction_hex": code.hex(),
                "scalars": dict(scalars),
                "memory": {str(k): v for k, v in sorted(initial.items())},
            }
            current = compiled
            assert current is not None
            try:
                after = emulate(code, before)
            except Exception as error:
                if not is_cpu_exception(error):
                    differences = (f"emulator {type(error).__name__}: {error}",)
                else:
                    differences = current.differences(before, "error")
            else:
                differences = current.differences(before, after)
            if differences:
                report["input"] = sample_input
                reproduced = True
                report["status"] = "mismatch"
                # Preserve the simplest observed witness if processing is interrupted;
                # explanation probes can otherwise overwrite it with large values.
                incumbent = report.get("witness")
                if incumbent is None or tuple(scalars.values()) < tuple(
                    incumbent[name] for name in scalars
                ):
                    report["differences"] = list(differences)
                    report["witness"] = dict(scalars)
                publish()
                raise _Mismatch(before, differences)

        agrees()

    try:
        total_budget = (
            min(examples, max_executions) if max_executions is not None else examples
        )
        count = len(campaign.models) if campaign is not None else 1
        for index in range(count):
            case_budget = total_budget // count + (index < total_budget % count)
            if case_budget:
                run_case(index, case_budget)
    except _InputAcquisitionError:
        pass
    except _Mismatch as mismatch:
        report["status"] = "mismatch"
        report["differences"] = list(mismatch.differences)
        report["witness"] = dict(mismatch.before.scalars)
        report["processing"] = "complete"
        if stage == "explain":
            report["explanation"] = list(getattr(mismatch, "__notes__", ()))
    except _ExecutionBudget:
        report["reason"] = "execution budget exhausted"
    else:
        if stage == "discover":
            report["status"] = "pass"
            report["processing"] = "complete"
        elif not reproduced:
            report[
                "reason"
            ] = "saved failure did not reproduce; discovery was not rerun"
    if campaign is not None:
        report.update(campaign.summary())
        report["status"] = (
            "mismatch"
            if campaign.disagreements
            else "incomplete"
            if campaign.unusable
            else "pass"
        )
    report.update(
        preparation_seconds=preparation_seconds,
        execution_seconds=perf_counter() - sampling_started,
        total_seconds=perf_counter() - started,
    )
    publish()
    return report


class CompiledModel:
    """Share a typed model once, then evaluate concrete witnesses without SMT."""

    def __init__(self, artifact: InstructionModel) -> None:
        self.artifact = share_expressions(artifact)
        self.steps = self.artifact.steps
        self.scalar_widths = {
            d.name: d.sort.require_bv_width()
            for d in artifact.declarations
            if d.name != MEMORY_NAME
        }
        memory = next(d for d in artifact.declarations if d.name == MEMORY_NAME)
        if memory.sort.require_array_widths() != (64, 8):
            raise TypeError("input memory is not a BV64-to-BV8 array")

    def differences(
        self,
        before: ConcreteState,
        after: ConcreteState | Literal["error"] | None,
        *,
        on_prediction=None,
        require_outcome=False,
    ) -> tuple[str, ...]:
        missing = self.scalar_widths.keys() - before.scalars.keys()
        if missing:
            raise ComparisonUnavailable(f"missing concrete inputs: {sorted(missing)}")
        environment = {
            name: value & ((1 << self.scalar_widths[name]) - 1)
            for name, value in before.scalars.items()
            if name in self.scalar_widths
        }
        environment[MEMORY_NAME] = ConcreteArray.memory(before.memory)
        evaluate = evaluator(environment)
        enabled = tuple(step for step in self.steps if evaluate(step.guard))
        if len(enabled) != 1:
            if require_outcome:
                raise ComparisonUnavailable(
                    f"enabled edges: {len(enabled)}; expected exactly one"
                )
            return (f"enabled edges: {len(enabled)}; expected exactly one",)
        step = enabled[0]
        updates = {a.name: a.value for a in step.simultaneous_update}
        if on_prediction is not None:
            from extractor.evidence_events import MemorySnapshot, ModelPrediction

            def prediction():
                return ModelPrediction(
                    tuple(
                        (name, evaluate(value))
                        for name, value in updates.items()
                        if name != MEMORY_NAME
                    ),
                    MemorySnapshot.capture(evaluate(updates[MEMORY_NAME]), 8),
                    step.target.kind,
                    evaluate(step.mirrored_pc),
                )

            on_prediction(prediction)
        if after is None:
            return ()
        if after == "error":
            return (
                ()
                if step.target.kind == "error"
                else (f"target: model={step.target.kind}, emulator=error",)
            )
        if step.target.kind == "error":
            return ("target: model=error, emulator=continued",)
        differences = [
            f"{name}: model={actual:#x}, emulator={expected:#x}"
            for name, expected in after.scalars.items()
            if name in updates
            and name != MEMORY_NAME
            and (actual := evaluate(updates[name])) != expected
        ]
        mirrored_pc = evaluate(step.mirrored_pc)
        if mirrored_pc != after.scalars["rip"]:
            differences.append(
                f"mirrored_pc: model={mirrored_pc:#x}, emulator="
                + f"{after.scalars['rip']:#x}"
            )
        if evaluate(updates[MEMORY_NAME]) != ConcreteArray.memory(after.memory):
            differences.append("memory differs")
        return tuple(differences)
