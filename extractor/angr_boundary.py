# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""The small Angr/Claripy surface used by the AMD64 adapter."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSet, Sequence
from typing import Protocol, cast

from extractor import runtime
from extractor.tool_errors import AngrOperationError


class Ast(Protocol):
    op: str
    args: tuple[object, ...]

    def __getitem__(self, key: int | slice) -> Ast:
        ...

    def __mul__(self, other: Ast) -> Ast:
        ...

    def zero_extend(self, bits: int) -> Ast:
        ...


class Registers(Protocol):
    rip: Ast
    rflags: Ast
    cc_op: Ast
    cc_dep1: Ast
    cc_dep2: Ast
    cc_ndep: Ast

    def __getattr__(self, name: str) -> Ast:
        ...


class Inspector(Protocol):
    address_concretization_action: str | None
    address_concretization_add_constraints: bool
    mem_read_address: Ast | None
    mem_read_expr: Ast | None
    mem_read_length: int | Ast
    mem_write_address: Ast | None
    mem_write_expr: Ast | None
    mem_write_length: int | Ast

    def b(
        self,
        event: str,
        *,
        when: object,
        action: Callable[[object], None],
    ) -> None:
        ...


class HistoryAction(Protocol):
    type: str
    action: str


class History(Protocol):
    recent_actions: Sequence[HistoryAction]
    jump_guard: Ast | None
    jumpkind: str


class Scratch(Protocol):
    exit_stmt_idx: int


class State(Protocol):
    globals: MutableMapping[str, object]
    history: History
    inspect: Inspector
    options: MutableSet[object]
    regs: Registers
    scratch: Scratch


class CapstoneBlock(Protocol):
    insns: Sequence[object]


class VexBlock(Protocol):
    instructions: int
    jumpkind: str
    statements: Sequence[object]
    tyenv: object


class Block(Protocol):
    bytes: bytes
    capstone: CapstoneBlock
    vex: VexBlock


class Successors(Protocol):
    all_successors: Sequence[State]


class Factory(Protocol):
    def blank_state(self, *, addr: int) -> State:
        ...

    def block(
        self, address: int, *, num_inst: int, byte_string: bytes | None = None
    ) -> Block:
        ...

    def successors(self, state: State, *, num_inst: int) -> Successors:
        ...


class Arch(Protocol):
    name: str
    bits: int
    registers: Mapping[str, tuple[int, int]]


class Project(Protocol):
    arch: Arch
    factory: Factory


class AngrOptions(Protocol):
    SYMBOLIC_WRITE_ADDRESSES: object
    TRACK_MEMORY_ACTIONS: object
    TRACK_REGISTER_ACTIONS: object
    UNDER_CONSTRAINED_SYMEXEC: object
    UNICORN: object


class Angr(Protocol):
    BP_AFTER: object
    BP_BEFORE: object
    options: AngrOptions


class Claripy(Protocol):
    def BVS(self, name: str, size: int, *, explicit_name: bool) -> Ast:
        ...

    def BVV(self, value: int, size: int) -> Ast:
        ...

    def Concat(self, *pieces: Ast) -> Ast:
        ...

    def Extract(self, high: int, low: int, value: Ast) -> Ast:
        ...

    def If(self, condition: object, then: Ast, otherwise: Ast) -> Ast:
        ...


angr = cast(Angr, cast(object, runtime.angr))
claripy = cast(Claripy, cast(object, runtime.claripy))


def expect_ast(value: object, field: str) -> Ast:
    base = getattr(runtime.claripy, "ast", None)
    base = getattr(base, "Base", None)
    if not isinstance(base, type) or not isinstance(value, base):
        raise TypeError(f"{field} is not a Claripy AST")
    return cast(Ast, value)


def ast_not_equal(left: Ast, right: object) -> Ast:
    """Apply Claripy's symbolic inequality across its untyped operator boundary."""

    return expect_ast(cast(object, left) != right, "Claripy inequality")


def expect_project(value: object) -> Project:
    project = getattr(runtime.angr, "Project", None)
    if not isinstance(project, type) or not isinstance(value, project):
        raise TypeError("project is not an Angr Project")
    return cast(Project, value)


def expect_state(value: object) -> State:
    state = getattr(runtime.angr, "SimState", None)
    if not isinstance(state, type) or not isinstance(value, state):
        raise TypeError("state is not an Angr SimState")
    return cast(State, value)


def lift_block(
    project: Project,
    address: int,
    *,
    num_inst: int,
    byte_string: bytes | None = None,
) -> Block:
    try:
        if byte_string is None:
            return project.factory.block(address, num_inst=num_inst)
        return project.factory.block(
            address, num_inst=num_inst, byte_string=byte_string
        )
    except Exception as error:
        raise AngrOperationError("angr.factory.block", error) from error


def blank_state(project: Project, address: int) -> State:
    try:
        return project.factory.blank_state(addr=address)
    except Exception as error:
        raise AngrOperationError("angr.factory.blank_state", error) from error


def execute_successors(project: Project, state: State, *, num_inst: int) -> Successors:
    try:
        return project.factory.successors(state, num_inst=num_inst)
    except Exception as error:
        raise AngrOperationError("angr.factory.successors", error) from error
