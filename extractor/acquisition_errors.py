# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
"""Expected limits of an individual acquisition attempt."""

from antiunification.many import IncompatibleShapes
from extractor.amd64_state import Amd64AdapterError
from extractor.artifact import UnsupportedTheoryError
from extractor.operand_slots import OperandDecodeError
from extractor.tool_errors import AngrOperationError, ShellcodeLoadError
from extractor.xed import EncodingError


EXPECTED_ACQUISITION = (
    Amd64AdapterError,
    UnsupportedTheoryError,
    OperandDecodeError,
    ShellcodeLoadError,
    AngrOperationError,
    EncodingError,
    IncompatibleShapes,
)
