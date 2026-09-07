# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
"""Acquire constructor cases once; retain models independently of AU success."""

from dataclasses import asdict, dataclass
from functools import cache

from antiunification.algebra import AlgebraError
from antiunification.many import antiunify_many
from extractor.acquisition_errors import EXPECTED_ACQUISITION
from extractor.artifact import InstructionModel, TermSort
from extractor.constructor_inputs import (
    ArgumentCase,
    Domain,
    argument_domain,
    checked_encode,
    register_domains,
    structural_cases,
    supported_register_values,
)
from extractor.evidence_events import AttemptContext
from extractor.extractor import _extract_concrete
from extractor.model_syntax import AddressAtom, BitVectorAtom, QFAbvSyntax
from extractor.normalization import normalize_model
from extractor.operand_slots import (
    OperandDecodeError,
    canonical_bindings,
    normalization_labels,
)
from extractor.runtime import load_shellcode
from extractor.xed import EncodingError, _invoke, decode, encode_constructor, registers


@cache
def _unicorn_register_names():
    from extractor.unicorn_boundary import amd64_register

    names = []
    for register in registers():
        try:
            amd64_register(register["name"])
        except TypeError:
            continue
        names.append(register["name"])
    return frozenset(names)


def _constructor_roles(form, domains, values=None):
    """Decode implicit operands at one canonical point in supported ranges."""
    values = tuple(domain.seed() for domain in domains) if values is None else values
    decoded = encode_constructor(form["id"], values)
    fixed = {
        op["register"]["parent"]
        for op in decoded["operands"]
        if op["visibility"] == "IMPLICIT" and op["register"]["name"] != "INVALID"
    }
    return decoded, fixed


def bindings(decoded, declarations, source):
    result = canonical_bindings(decoded, declarations, source)
    result["SOURCE_address"] = AddressAtom(source)
    numbers = {"SOURCE": source, "NEXT": source + decoded["length"]}
    if decoded["base"]["name"] in {"RIP", "EIP"}:
        numbers["MEM_ADDRESS"] = source + decoded["length"] + decoded["displacement"]
    if decoded["displacement_width"]:
        numbers["DISPLACEMENT"] = decoded["displacement"]
    width = max(
        (
            op["width"]
            for op in decoded["operands"]
            if op["name"] in {"MEM0", "MEM1", "AGEN"}
        ),
        default=0,
    )
    for name, value in numbers.items():
        result[name + "_bv"] = BitVectorAtom(value % (1 << 64), TermSort.bv(64))
        result[name + "_address"] = AddressAtom(value % (1 << 64))
        if name in {"MEM_ADDRESS", "DISPLACEMENT"}:
            for offset in range(1, (width + 7) // 8):
                result[f"{name}_BYTE_{offset}"] = BitVectorAtom(
                    (value + offset) % (1 << 64), TermSort.bv(64)
                )
    # Literal stores may expose individual slices of immediate/return-address data.
    for name in ["IMM0", "NEXT_bv"]:
        atom = result.get(name)
        if isinstance(atom, BitVectorAtom):
            for width in (8, 16, 32):
                for offset in range(0, atom.sort.width, width):
                    result[f"{name}_SLICE_{width}_{offset}"] = BitVectorAtom(
                        (atom.value >> offset) % (1 << width), TermSort.bv(width)
                    )
    return result


def generalize(observations):
    models, rows = [], []
    for code, decoded, model in observations:
        row = bindings(decoded, model.declarations, model.source)
        rows.append(row)
        models.append(normalize_model(model, normalization_labels(row)))
    if not models or any(row.keys() != rows[0].keys() for row in rows):
        raise OperandDecodeError("constructor observations have incompatible bindings")
    columns = {}
    for name in rows[0]:
        column = tuple(row[name] for row in rows)
        if len(set(column)) > 1 and column not in columns.values():
            columns[name] = column
    try:
        result = antiunify_many(QFAbvSyntax(), models, correspondences=columns)
    except AlgebraError as error:
        raise OperandDecodeError(f"AU algebra: {error}") from error
    unexplained = set(result.substitutions[0]) - columns.keys()
    if unexplained:
        raise OperandDecodeError(
            f"AU differences unexplained by parameters: {sorted(unexplained)}"
        )
    return result


def comparison_available(code, decoded, source, on_finding, attempt):
    from extractor.amd64_state import FLAG_NAMES, GPR64, YMM256
    from extractor.fuzzer import InputLayout, _input_state, emulate
    from extractor.unicorn_boundary import is_cpu_exception, is_emulator_error

    values = tuple(0x100000 if name in GPR64 else 0 for name in GPR64 + YMM256)
    before = _input_state(
        code,
        source,
        {},
        bytes(32),
        values,
        [False] * len(FLAG_NAMES),
        True,
        layout=InputLayout.from_decoded(decoded),
    )
    try:
        emulate(code, before)
    except Exception as error:
        if not is_emulator_error(error):
            raise
        if is_cpu_exception(error):
            return True  # A modeled CPU fault is a usable execution outcome.
        on_finding(f"comparison:source:{source:x}", code, error, attempt)
        return False
    return True


@dataclass
class PreparedCase:
    arguments: ArgumentCase
    observations: tuple
    template: object | None
    comparable: tuple[bool, ...] = ()

    def instantiate(self, values, source):
        decoded = checked_encode(self.arguments.form, values)
        prototype = self.observations[0][2]
        row = bindings(decoded, prototype.declarations, source)
        model = self.template.instantiate(
            {name: row[name] for name in self.template.substitutions[0]}
        )
        return bytes.fromhex(decoded["hex"]), decoded, model

    def to_data(self):
        return {
            "form": self.arguments.form,
            "domains": [asdict(d) for d in self.arguments.domains],
            "groups": self.arguments.groups,
            "generalized": self.template is not None,
            "comparable": self.comparable,
            "observations": [
                {
                    "instruction_hex": code.hex(),
                    "decoded": decoded,
                    "model": model.to_data(),
                }
                for code, decoded, model in self.observations
            ],
        }

    @classmethod
    def from_data(cls, data):
        arguments = ArgumentCase(
            data["form"],
            tuple(
                Domain(tuple(d["choices"]), d["low"], d["high"], d["register"])
                for d in data["domains"]
            ),
            tuple(tuple(g) for g in data["groups"]),
        )
        observations = tuple(
            (
                bytes.fromhex(o["instruction_hex"]),
                o["decoded"],
                InstructionModel.from_data(o["model"]),
            )
            for o in data["observations"]
        )
        return cls(
            arguments,
            observations,
            generalize(observations) if data["generalized"] else None,
            tuple(data.get("comparable", [True] * len(observations))),
        )


def prepare_catalog(instruction, source, *, on_model, on_finding):
    from extractor.angr_boundary import expect_project, lift_block

    forms = _invoke("forms", decode(instruction)["iclass"])
    project = expect_project(load_shellcode(instruction, source))
    arch = project.arch
    supported = supported_register_values(
        frozenset(arch.registers), _unicorn_register_names()
    )
    domain_table = register_domains(supported)
    cache = {}
    model_ids = {}
    argument_values = {}
    comparisons = {}
    cases = []

    def attempt(
        operation,
        form,
        *,
        arguments=None,
        case_index=None,
        values=None,
        address=None,
        code=None,
        identifiers=(),
    ):
        return AttemptContext(
            operation=operation,
            constructor_id=form["id"],
            case_index=case_index,
            domains=(
                tuple(
                    (domain.choices, domain.low, domain.high, domain.register)
                    for domain in arguments.domains
                )
                if arguments is not None
                else None
            ),
            alias_groups=arguments.groups if arguments is not None else None,
            arguments=values,
            source=address,
            encoding=code,
            model_ids=tuple(identifier for identifier in identifiers if identifier),
        )

    for form in forms:
        domains = ()
        canonical = None
        try:
            domains = tuple(
                argument_domain(argument, domain_table) for argument in form["args"]
            )
            canonical = tuple(domain.seed() for domain in domains)
            decoded, fixed = _constructor_roles(form, domains, canonical)
        except EncodingError as error:
            on_finding(
                f"generation:constructor:{form['id']}",
                instruction,
                error,
                attempt(
                    "constructor-preflight",
                    form,
                    values=canonical,
                    address=source,
                ),
            )
            continue
        try:
            code = bytes.fromhex(decoded["hex"])
            block = lift_block(project, source, num_inst=1, byte_string=code)
            if not (
                block.vex.instructions == 1
                and block.vex.jumpkind != "Ijk_NoDecode"
                and block.bytes == code
            ):
                raise OperandDecodeError("angr cannot lift canonical constructor form")
        except EXPECTED_ACQUISITION as error:
            on_finding(
                f"extraction:constructor:{form['id']}",
                code,
                error,
                attempt(
                    "lift-preflight",
                    form,
                    values=canonical,
                    address=source,
                    code=code,
                ),
            )
            continue
        for case_index, arguments in enumerate(structural_cases(form, domains, fixed)):
            baseline = None
            try:
                baseline = arguments.canonical()
                checked_encode(form, baseline)
            except EncodingError as error:
                on_finding(
                    f"generation:constructor:{form['id']}:case:{case_index}",
                    instruction,
                    error,
                    attempt(
                        "semantic-case",
                        form,
                        arguments=arguments,
                        case_index=case_index,
                        values=baseline,
                        address=source,
                    ),
                )
                continue
            requests = [(v, source) for v in arguments.separating(baseline)]
            requests.append(
                (
                    baseline,
                    (
                        0xFFFFFEDCBA987654
                        if source != 0xFFFFFEDCBA987654
                        else 0x1234567890AB
                    ),
                )
            )
            observations, incomplete = [], False
            for values, address in requests:
                try:
                    decoded = checked_encode(form, values)
                except EncodingError as error:
                    incomplete = True
                    on_finding(
                        f"generation:constructor:{form['id']}:case:{case_index}",
                        instruction,
                        error,
                        attempt(
                            "constructor-generation",
                            form,
                            arguments=arguments,
                            case_index=case_index,
                            values=values,
                            address=address,
                        ),
                    )
                    continue
                code = bytes.fromhex(decoded["hex"])
                key = code, address
                argument_values.setdefault(key, values)
                if key not in cache:
                    try:
                        cache[key] = _extract_concrete(
                            load_shellcode(code, address), address
                        )
                        model_ids[key] = on_model(code, cache[key], "direct")
                    except EXPECTED_ACQUISITION as error:
                        cache[key] = None
                        on_finding(
                            f"extraction:constructor:{form['id']}:source:{address:x}",
                            code,
                            error,
                            attempt(
                                "extraction",
                                form,
                                arguments=arguments,
                                case_index=case_index,
                                values=values,
                                address=address,
                                code=code,
                            ),
                        )
                model = cache[key]
                if model is None:
                    incomplete = True
                else:
                    observations.append((code, decoded, model))
            if not observations:
                continue
            template = None
            try:
                if incomplete:
                    raise OperandDecodeError(
                        "incomplete constructor AU observations; direct models retained"
                    )
                template = generalize(observations)
            except EXPECTED_ACQUISITION as error:
                on_finding(
                    f"generalization:constructor:{form['id']}",
                    observations[0][0],
                    error,
                    attempt(
                        "generalization",
                        form,
                        arguments=arguments,
                        case_index=case_index,
                        values=baseline,
                        address=observations[0][2].source,
                        code=observations[0][0],
                        identifiers=(
                            model_ids.get((code, model.source))
                            for code, _decoded, model in observations
                        ),
                    ),
                )
            for code, decoded, model in observations:
                key = code, model.source
                if key not in comparisons:
                    comparisons[key] = comparison_available(
                        code,
                        decoded,
                        model.source,
                        on_finding,
                        attempt(
                            "comparison-preflight",
                            form,
                            arguments=arguments,
                            case_index=case_index,
                            values=argument_values.get(key),
                            address=model.source,
                            code=code,
                            identifiers=(model_ids.get(key),),
                        ),
                    )
            comparable = tuple(
                comparisons[code, model.source] for code, decoded, model in observations
            )
            cases.append(
                PreparedCase(arguments, tuple(observations), template, comparable)
            )
    return cases
