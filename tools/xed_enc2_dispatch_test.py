# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from dataclasses import dataclass
import unittest

from tools.xed_enc2_dispatch import arguments


@dataclass
class Operand:
    name: str
    visibility: str = "EXPLICIT"


@dataclass
class Record:
    parsed_operands: list[Operand]


@dataclass
class Function:
    args: list[tuple[str, str]]

    def get_args(self):
        return self.args


class ArgumentTests(unittest.TestCase):
    def test_fixed_register_is_not_an_encoder_argument(self):
        values, checks = arguments(
            Record([Operand("REG0", "IMPLICIT"), Operand("REG1", "DEFAULT")]),
            Function([("xed_enc2_req_t* r", "req"), ("xed_reg_enum_t reg0", "gpr64")]),
        )
        self.assertIn("XED_OPERAND_REG1", values[1])
        self.assertIn("== 64", checks[0])

    def test_address_arguments_do_not_consume_register_operands(self):
        values, _ = arguments(
            Record([Operand("MEM0"), Operand("REG0")]),
            Function(
                [
                    ("xed_enc2_req_t* r", "req"),
                    ("xed_reg_enum_t base", "gpr64"),
                    ("xed_reg_enum_t index", "gpr64_index"),
                    ("xed_uint_t scale", "scale"),
                    ("xed_int8_t disp8", "int8"),
                    ("xed_reg_enum_t reg0", "gpr64"),
                ]
            ),
        )
        self.assertIn("get_base_reg", values[1])
        self.assertIn("get_index_reg", values[2])
        self.assertIn("XED_OPERAND_REG0", values[-1])

    def test_unknown_arguments_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "unmapped encoder argument"):
            arguments(Record([]), Function([("xed_uint_t mystery", "mystery")]))

    def test_missing_register_argument_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "exceed encoder arguments"):
            arguments(Record([Operand("REG0")]), Function([]))

    def test_extra_register_argument_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "exceed explicit operands"):
            arguments(Record([]), Function([("xed_reg_enum_t reg0", "gpr64")]))


if __name__ == "__main__":
    unittest.main()
