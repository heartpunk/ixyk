# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Test scaffolding for the adapter contract, not the production JSON backend."""

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
import json
import sys
import types
from typing import Callable, Literal, Union, get_args, get_origin, get_type_hints

from extractor.evidence import TypeSchema


@dataclass
class _Plan:
    encode: Callable = lambda value: value
    decode: Callable = lambda value: value


def _plans():
    cache = {}

    def prepare(annotation):
        if annotation in cache:
            return cache[annotation]
        plan = cache[annotation] = _Plan()
        origin, args = get_origin(annotation), get_args(annotation)
        if annotation in (str, int, bool, float, type(None)):

            def scalar(value):
                if type(value) is not annotation:
                    raise TypeError(f"expected {annotation}, got {type(value)}")
                return value

            plan.encode = plan.decode = scalar
        elif annotation is bytes:
            plan.encode = lambda value: base64.b64encode(value).decode("ascii")
            plan.decode = lambda value: base64.b64decode(value, validate=True)
        elif origin is Literal:

            def literal(value):
                if not any(type(value) is type(v) and value == v for v in args):
                    raise ValueError(f"expected one of {args}")
                return value

            plan.encode = plan.decode = literal
        elif origin in (Union, types.UnionType):
            choices = [(t, prepare(t)) for t in args if t is not type(None)]
            nullable = type(None) in args
            if len(choices) == 1 and nullable:
                child = choices[0][1]
                plan.encode = lambda value: (
                    None if value is None else child.encode(value)
                )
                plan.decode = lambda value: (
                    None if value is None else child.decode(value)
                )
            else:

                def encode_union(value):
                    if value is None and nullable:
                        return None
                    for index, (kind, child) in enumerate(choices):
                        if type(value) is (get_origin(kind) or kind):
                            return [index, child.encode(value)]
                    raise TypeError(f"value does not match union {annotation}")

                def decode_union(value):
                    if value is None and nullable:
                        return None
                    if (
                        not isinstance(value, list)
                        or len(value) != 2
                        or type(value[0]) is not int
                        or not 0 <= value[0] < len(choices)
                    ):
                        raise ValueError("invalid union discriminator")
                    return choices[value[0]][1].decode(value[1])

                plan.encode, plan.decode = encode_union, decode_union
        elif is_dataclass(annotation):
            hints = get_type_hints(annotation)
            members = tuple(
                (f.name, prepare(hints[f.name])) for f in fields(annotation)
            )
            plan.encode = lambda value: {
                name: child.encode(getattr(value, name)) for name, child in members
            }

            def decode_object(value):
                if not isinstance(value, dict) or value.keys() != {
                    n for n, _ in members
                }:
                    raise ValueError(f"fields do not match {annotation}")
                return annotation(**{n: child.decode(value[n]) for n, child in members})

            plan.decode = decode_object
        elif origin in (dict, Mapping):
            key, item = map(prepare, args)
            if args[0] is str:
                plan.encode = lambda value: {
                    key.encode(k): item.encode(v) for k, v in value.items()
                }
                plan.decode = lambda value: {
                    key.decode(k): item.decode(v) for k, v in value.items()
                }
            else:
                plan.encode = lambda value: [
                    [key.encode(k), item.encode(v)] for k, v in value.items()
                ]
                plan.decode = lambda value: {
                    key.decode(k): item.decode(v) for k, v in value
                }
        elif origin in (tuple, list, Sequence):
            constructor = tuple if origin is tuple else list
            if origin is not tuple or (len(args) == 2 and args[1] is Ellipsis):
                child = prepare(args[0])
                plan.encode = lambda value: [child.encode(v) for v in value]
                plan.decode = lambda value: constructor(child.decode(v) for v in value)
            else:
                children = tuple(map(prepare, args))
                plan.encode = lambda value: [
                    p.encode(v) for p, v in zip(children, value, strict=True)
                ]
                plan.decode = lambda value: tuple(
                    p.decode(v) for p, v in zip(children, value, strict=True)
                )
        else:
            raise TypeError(
                f"JSON evidence codec needs a representation for {annotation}"
            )
        return plan

    return prepare


@dataclass
class _JSONCodec:
    schema: TypeSchema
    plan: _Plan

    def encode(self, value: object) -> bytes:
        value = self.plan.encode(self.schema.project(value))
        return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def decode(self, data: bytes) -> object:
        return self.schema.restore(self.plan.decode(json.loads(data)))


class ReferenceJSONBackend:
    name = "ixyk.reference-json.v1"

    def prepare(self, schema: TypeSchema) -> _JSONCodec:
        # Concrete memory is a nested Store expression (up to ~1K bytes).
        # Keep the reference codec recursive; allow its normal encode/decode depth.
        if sys.getrecursionlimit() < 10_000:
            sys.setrecursionlimit(10_000)
        return _JSONCodec(schema, _plans()(schema.representation))
