"""Extract ADD once, then run the production differential fuzzer."""

from extractor.runtime import load_shellcode

from extractor.artifact import InstructionModel
from extractor.extractor import extract
from extractor.fuzzer import fuzz


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")


def main() -> None:
    extracted = extract(load_shellcode(ADD_RAX_RBX, SOURCE), SOURCE)
    encoded = extracted.to_json()
    model = InstructionModel.from_json(encoded)
    report = fuzz(model, ADD_RAX_RBX, examples=100)
    assert report["status"] == "pass", report
    print(encoded)


if __name__ == "__main__":
    main()
