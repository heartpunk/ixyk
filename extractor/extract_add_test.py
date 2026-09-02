"""Execute one real extraction as a remote-testable action."""

from extractor.runtime import load_shellcode
from extractor.artifact import InstructionModel
from extractor.extractor import extract


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")


def main() -> None:
    model = extract(load_shellcode(ADD_RAX_RBX, SOURCE), SOURCE)
    encoded = model.to_json()
    assert InstructionModel.from_json(encoded) == model
    print(encoded)


if __name__ == "__main__":
    main()
