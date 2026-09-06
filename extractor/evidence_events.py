# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Immutable semantic observations emitted by the acquisition/fuzz boundaries."""

from dataclasses import dataclass
from typing import Literal

from extractor.artifact import InstructionModel, TypedExpr
from extractor.evidence import TypeRegistry


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
class Finding:
    stage: str
    instruction: bytes
    error_kind: str
    message: str


@dataclass(frozen=True)
class ToolFailure:
    stage: str
    instruction: bytes
    tool: str
    error_kind: str
    message: str
    traceback: str
    before: StateSnapshot | None


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

    def finding(self, stage, code, error, *, context=None, before=None):
        tool = getattr(error, "tool", None)
        if tool is None:
            value = Finding(stage, code, type(error).__name__, str(error))
        else:
            value = ToolFailure(
                stage,
                code,
                tool,
                error.error_kind,
                error.error_message,
                error.formatted_traceback,
                StateSnapshot.capture(before) if before is not None else None,
            )
        self.recorder.emit(value, context=context)
