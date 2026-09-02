"""The extractor admits declared scalar and vector architectural state."""

from extractor.runtime import load_shellcode

from extractor.extractor import extract


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")
MOVQ_XMM0_RAX = bytes.fromhex("66480f6ec0")
PMOVMSKB_EAX_XMM0 = bytes.fromhex("660fd7c0")


def test_scalar_instruction_remains_admitted() -> None:
    assert extract(load_shellcode(ADD_RAX_RBX, SOURCE), SOURCE).steps


def test_vector_register_access_is_admitted() -> None:
    for instruction in MOVQ_XMM0_RAX, PMOVMSKB_EAX_XMM0:
        assert extract(load_shellcode(instruction, SOURCE), SOURCE).steps


def main() -> None:
    test_scalar_instruction_remains_admitted()
    test_vector_register_access_is_admitted()


if __name__ == "__main__":
    main()
