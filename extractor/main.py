"""Emit one real AMD64 instruction's typed semantic model."""

from extractor.extractor import extract
from extractor.runtime import load_shellcode


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")


def main() -> None:
    project = load_shellcode(ADD_RAX_RBX, SOURCE)
    print(extract(project, SOURCE).to_json())


if __name__ == "__main__":
    main()
