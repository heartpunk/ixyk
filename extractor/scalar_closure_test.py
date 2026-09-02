"""The scalar extractor must reject undeclared architectural state."""

from extractor.runtime import load_shellcode

import pytest

from extractor.amd64_state import Amd64AdapterError
from extractor.extractor import extract


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")
MOVQ_XMM0_RAX = bytes.fromhex("66480f6ec0")
PMOVMSKB_EAX_XMM0 = bytes.fromhex("660fd7c0")


def test_scalar_instruction_remains_admitted() -> None:
    assert extract(load_shellcode(ADD_RAX_RBX, SOURCE), SOURCE).steps


@pytest.mark.parametrize(
    ("instruction", "operation"),
    ((MOVQ_XMM0_RAX, "write"), (PMOVMSKB_EAX_XMM0, "read")),
)
def test_vector_register_access_fails_closed(
    instruction: bytes, operation: str
) -> None:
    with pytest.raises(
        Amd64AdapterError, match=rf"{operation} .* escapes scalar state"
    ):
        _ = extract(load_shellcode(instruction, SOURCE), SOURCE)
