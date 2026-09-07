# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Typed evidence records with codec-independent provenance and framing."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, fields, is_dataclass
import json
import struct
import time
from typing import BinaryIO, Protocol, get_type_hints
from uuid import uuid4


def _identity(value: object) -> object:
    return value


@dataclass(frozen=True)
class TypeSchema:
    kind: str
    python_type: type
    representation: type
    fields: tuple[tuple[str, object], ...]
    project: Callable[[object], object] = _identity
    restore: Callable[[object], object] = _identity

    def descriptor(self) -> dict[str, str]:
        def name(cls: type) -> str:
            return f"{cls.__module__}.{cls.__qualname__}"

        return {
            "kind": self.kind,
            "python_type": name(self.python_type),
            "representation": name(self.representation),
        }


class TypeRegistry:
    def __init__(self) -> None:
        self._types: dict[type, TypeSchema] = {}

    def register(
        self,
        cls: type,
        *,
        kind: str,
        representation: type | None = None,
        project: Callable[[object], object] = _identity,
        restore: Callable[[object], object] = _identity,
    ) -> None:
        if (
            not kind
            or cls in self._types
            or any(item.kind == kind for item in self._types.values())
        ):
            raise ValueError("evidence type and kind must be unique and nonempty")
        wire = representation or cls
        if not is_dataclass(wire):
            raise TypeError("register a dataclass or supply a dataclass representation")
        hints = get_type_hints(wire)
        self._types[cls] = TypeSchema(
            kind,
            cls,
            wire,
            tuple((field.name, hints[field.name]) for field in fields(wire)),
            project,
            restore,
        )

    def schemas(self) -> tuple[TypeSchema, ...]:
        return tuple(sorted(self._types.values(), key=lambda item: item.kind))


class Codec(Protocol):
    def encode(self, value: object) -> bytes: ...
    def decode(self, data: bytes) -> object: ...


class Backend(Protocol):
    # Includes the codec version; readers supply the matching implementation.
    name: str

    def prepare(self, schema: TypeSchema) -> Codec: ...


@dataclass(frozen=True)
class RunContext:
    commit: str
    invocation_id: str

    def __post_init__(self) -> None:
        if not self.commit or not self.invocation_id:
            raise ValueError("source commit and Bazel invocation ID are required")


@dataclass(frozen=True)
class Record:
    id: str
    timestamp_ns: int
    context: str | None
    value: object


class TruncatedRecord(EOFError):
    """The stream ended inside a frame; earlier yielded records remain usable."""


_MAGIC = b"IXYK-EVIDENCE\x01"
_LENGTH = struct.Struct(">Q")
_RECORD = struct.Struct(">IQQI")  # kind ID, sequence, timestamp, context byte length


def _read(stream: BinaryIO, size: int) -> bytes:
    parts = bytearray()
    while len(parts) < size:
        chunk = stream.read(size - len(parts))
        if not chunk:
            raise TruncatedRecord(f"needed {size} bytes, received {len(parts)}")
        parts.extend(chunk)
    return bytes(parts)


class EvidenceAdapter:
    def __init__(
        self,
        *,
        backend: Backend,
        types: TypeRegistry,
        run: RunContext,
        output: BinaryIO,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        schemas = types.schemas()
        self._codecs = {
            schema.python_type: (index, backend.prepare(schema))
            for index, schema in enumerate(schemas)
        }
        self._output, self._clock = output, clock
        self._sequence, self._failed = 0, False
        self.stream_id = str(uuid4())
        self.manifest = {
            "version": 1,
            "backend": backend.name,
            "stream_id": self.stream_id,
            "commit": run.commit,
            "invocation_id": run.invocation_id,
            "types": [schema.descriptor() for schema in schemas],
        }
        header = json.dumps(self.manifest, separators=(",", ":")).encode()
        self._write(_MAGIC + _LENGTH.pack(len(header)) + header)

    def _write(self, data: bytes) -> None:
        if self._failed:
            raise OSError("evidence stream failed during an earlier write")
        self._failed = True
        if self._output.write(data) != len(data):
            raise OSError("short evidence write")
        self._failed = False

    def emit(
        self,
        value: object,
        *,
        context: str | None = None,
        timestamp_ns: int | None = None,
    ) -> str:
        kind, codec = self._codecs[type(value)]
        payload = codec.encode(value)
        context_bytes = context.encode("utf-8") if context is not None else b""
        if context == "":
            raise ValueError("context must be nonempty or None")
        sequence = self._sequence
        timestamp = self._clock() if timestamp_ns is None else timestamp_ns
        metadata = _RECORD.pack(kind, sequence, timestamp, len(context_bytes))
        body = metadata + context_bytes + payload
        self._write(_LENGTH.pack(len(body)) + body)
        self._sequence += 1
        return f"{self.stream_id}:{sequence}"

    def flush(self) -> None:
        # The caller owns the stream, compression, flush cadence, and durability.
        if self._failed:
            raise OSError("evidence stream failed during an earlier write")
        self._failed = True
        self._output.flush()
        self._failed = False


class EvidenceReader:
    def __init__(self, source: BinaryIO, *, backend: Backend, types: TypeRegistry):
        if _read(source, len(_MAGIC)) != _MAGIC:
            raise ValueError("not an evidence v1 stream")
        size = _LENGTH.unpack(_read(source, _LENGTH.size))[0]
        self.manifest = json.loads(_read(source, size))
        schemas = types.schemas()
        if (
            self.manifest["version"] != 1
            or self.manifest["backend"] != backend.name
            or self.manifest["types"] != [s.descriptor() for s in schemas]
        ):
            raise ValueError("reader backend or type registry does not match stream")
        self._codecs = tuple(backend.prepare(schema) for schema in schemas)
        self._source = source

    def __iter__(self) -> Iterator[Record]:
        while True:
            first = self._source.read(1)
            if not first:
                return
            size = _LENGTH.unpack(first + _read(self._source, _LENGTH.size - 1))[0]
            body = _read(self._source, size)
            if len(body) < _RECORD.size:
                raise ValueError("evidence frame has no complete record header")
            kind, sequence, timestamp, length = _RECORD.unpack_from(body)
            end = _RECORD.size + length
            if kind >= len(self._codecs) or end > len(body):
                raise ValueError("invalid evidence kind or context length")
            context = body[_RECORD.size : end].decode("utf-8") or None
            value = self._codecs[kind].decode(body[end:])
            yield Record(
                f"{self.manifest['stream_id']}:{sequence}", timestamp, context, value
            )
