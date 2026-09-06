# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Small typed boundary around Unicorn's dynamically typed Python API."""

from __future__ import annotations

from collections.abc import Callable
import importlib
from types import ModuleType
from typing import Protocol, cast


class Emulator(Protocol):
    def ctl_set_tlb_mode(self, mode: int) -> None:
        ...

    def mem_map(self, address: int, size: int) -> None:
        ...

    def mem_write(self, address: int, data: bytes) -> None:
        ...

    def mem_read(self, address: int, size: int) -> bytearray:
        ...

    def reg_write(self, register: int, value: int) -> None:
        ...

    def reg_read(self, register: int) -> int:
        ...

    def hook_add(
        self,
        hook_type: int,
        callback: Callable[..., object],
        user_data: object | None = None,
        begin: int = 1,
        end: int = 0,
        *arguments: int,
    ) -> object:
        ...

    def emu_start(
        self, begin: int, until: int, timeout: int = 0, count: int = 0
    ) -> None:
        ...


def _constant(module: ModuleType, name: str) -> int:
    value: object = getattr(module, name, None)
    if type(value) is not int:
        raise TypeError(f"{module.__name__}.{name} is unavailable")
    return value


_unicorn = importlib.import_module("unicorn")
_x86 = importlib.import_module("unicorn.x86_const")
_factory_value: object = getattr(_unicorn, "Uc", None)
if not callable(_factory_value):
    raise TypeError("unicorn.Uc is unavailable")
_factory = cast(Callable[[int, int], Emulator], _factory_value)
_error_value: object = getattr(_unicorn, "UcError", None)
if not isinstance(_error_value, type) or not issubclass(_error_value, BaseException):
    raise TypeError("unicorn.UcError is unavailable")
_error = _error_value


def amd64_emulator() -> Emulator:
    emulator = _factory(
        _constant(_unicorn, "UC_ARCH_X86"),
        _constant(_unicorn, "UC_MODE_64"),
    )
    # The semantic model uses flat 64-bit addresses, not a configured guest MMU.
    emulator.ctl_set_tlb_mode(_constant(_unicorn, "UC_TLB_VIRTUAL"))
    return emulator


def amd64_register(name: str) -> int:
    return _constant(_x86, f"UC_X86_REG_{name.upper()}")


def unicorn_constant(name: str) -> int:
    return _constant(_unicorn, name)


def is_cpu_exception(error: BaseException) -> bool:
    return isinstance(error, _error) and getattr(
        error, "errno", None
    ) == unicorn_constant("UC_ERR_EXCEPTION")


def is_emulator_error(error: BaseException) -> bool:
    return isinstance(error, _error)
