# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Immutable semantic observations emitted by the acquisition/fuzz boundaries."""

from dataclasses import dataclass
from typing import Literal

from extractor.artifact import InstructionModel, TypedExpr
from extractor.evidence import TypeRegistry


@dataclass(frozen=True)
class AttemptContext:
    operation: str
    constructor_id: int | None = None
    case_index: int | None = None
    domains: tuple[tuple[tuple[int, ...], int, int, bool], ...] | None = None
    alias_groups: tuple[tuple[int, ...], ...] | None = None
    arguments: tuple[int, ...] | None = None
    source: int | None = None
    encoding: bytes | None = None
    model_ids: tuple[str, ...] = ()
    fuzz_input_id: str | None = None

    def to_data(self):
        return {
            "operation": self.operation,
            "constructor_id": self.constructor_id,
            "case_index": self.case_index,
            "domains": self.domains,
            "alias_groups": self.alias_groups,
            "arguments": self.arguments,
            "source": self.source,
            "encoding_hex": self.encoding.hex() if self.encoding is not None else None,
            "model_ids": self.model_ids,
            "fuzz_input_id": self.fuzz_input_id,
        }

    @classmethod
    def from_data(cls, data):
        if data is None:
            return None
        return cls(
            operation=data["operation"],
            constructor_id=data.get("constructor_id"),
            case_index=data.get("case_index"),
            domains=(
                tuple(
                    (tuple(choices), low, high, register)
                    for choices, low, high, register in data["domains"]
                )
                if data.get("domains") is not None
                else None
            ),
            alias_groups=(
                tuple(tuple(group) for group in data["alias_groups"])
                if data.get("alias_groups") is not None
                else None
            ),
            arguments=(
                tuple(data["arguments"]) if data.get("arguments") is not None else None
            ),
            source=data.get("source"),
            encoding=(
                bytes.fromhex(data["encoding_hex"])
                if data.get("encoding_hex") is not None
                else None
            ),
            model_ids=tuple(data.get("model_ids", ())),
            fuzz_input_id=data.get("fuzz_input_id"),
        )


@dataclass(frozen=True)
class StateSnapshot:
    scalars: tuple[tuple[str, int], ...]
    memory: tuple[tuple[int, int], ...]

    @classmethod
    def capture(cls, state):
        return cls(tuple(state.scalars.items()), tuple(state.memory.items()))


@dataclass(frozen=True)
class Acquisition:
    instruction: bytes
    source: int
    route: Literal["direct", "normalized", "generalized"]
    model_id: str


@dataclass(frozen=True)
class GeneralizationInputs:
    constructor: int
    models: tuple[tuple[bytes, int, str], ...]


@dataclass(frozen=True)
class ModelInstantiation:
    generalization_id: str
    arguments: tuple[int, ...]
    source: int


@dataclass(frozen=True)
class Finding:
    stage: str
    instruction: bytes
    error_kind: str
    message: str
    attempt: AttemptContext | None = None


@dataclass(frozen=True)
class ToolFailure:
    stage: str
    instruction: bytes
    tool: str
    error_kind: str
    message: str
    traceback: str
    before: StateSnapshot | None
    attempt: AttemptContext | None = None


@dataclass(frozen=True)
class FuzzInput:
    sample: int
    instruction: bytes
    before: StateSnapshot
    model_id: str | None
    route: Literal["generalized", "fallback", "unavailable"]


@dataclass(frozen=True)
class ModelPrediction:
    scalars: tuple[tuple[str, int], ...]
    memory: TypedExpr
    target: str
    mirrored_pc: int


@dataclass(frozen=True)
class Comparison:
    outcome: Literal["agreement", "disagreement", "unusable"]
    model_after: ModelPrediction | None
    reference_after: StateSnapshot | None
    reference_outcome: str
    differences: tuple[str, ...]


def evidence_types():
    registry = TypeRegistry()
    for cls, kind in (
        (InstructionModel, "instruction_model"),
        (Acquisition, "acquisition"),
        (GeneralizationInputs, "generalization_inputs"),
        (ModelInstantiation, "model_instantiation"),
        (Finding, "finding"),
        (ToolFailure, "tool_failure"),
        (FuzzInput, "fuzz_input"),
        (Comparison, "comparison"),
    ):
        registry.register(cls, kind=kind)
    return registry


class EvidenceHooks:
    def __init__(self, recorder):
        self.recorder = recorder
        self._models = {}

    def model(self, code, model, route, *, context=None):
        # InstructionModel and its entire expression tree are frozen dataclasses.
        identifier = self._models.get(model)
        if identifier is None:
            identifier = self.recorder.emit(model, context=context)
            self._models[model] = identifier
        self.recorder.emit(
            Acquisition(code, model.source, route, identifier), context=context
        )
        return identifier

    def finding(self, stage, code, error, *, context=None, before=None, attempt=None):
        tool = getattr(error, "tool", None)
        if tool is None:
            value = Finding(stage, code, type(error).__name__, str(error), attempt)
        else:
            value = ToolFailure(
                stage,
                code,
                tool,
                error.error_kind,
                error.error_message,
                error.formatted_traceback,
                StateSnapshot.capture(before) if before is not None else None,
                attempt,
            )
        self.recorder.emit(value, context=context)
