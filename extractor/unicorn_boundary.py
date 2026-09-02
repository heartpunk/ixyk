"""Small typed boundary around Unicorn's dynamically typed Python API."""

from __future__ import annotations

from collections.abc import Callable
import importlib
from types import ModuleType
from typing import Protocol, cast


class Emulator(Protocol):
    def mem_map(self, address: int, size: int) -> None: ...
    def mem_write(self, address: int, data: bytes) -> None: ...
    def mem_read(self, address: int, size: int) -> bytearray: ...
    def reg_write(self, register: int, value: int) -> None: ...
    def reg_read(self, register: int) -> int: ...
    def hook_add(
        self,
        hook_type: int,
        callback: Callable[..., object],
        user_data: object | None = None,
        begin: int = 1,
        end: int = 0,
        *arguments: int,
    ) -> object: ...
    def emu_start(
        self, begin: int, until: int, timeout: int = 0, count: int = 0
    ) -> None: ...


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


def amd64_emulator() -> Emulator:
    return _factory(
        _constant(_unicorn, "UC_ARCH_X86"),
        _constant(_unicorn, "UC_MODE_64"),
    )


def amd64_register(name: str) -> int:
    return _constant(_x86, f"UC_X86_REG_{name.upper()}")


def unicorn_constant(name: str) -> int:
    return _constant(_unicorn, name)
