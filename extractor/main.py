"""Emit one real AMD64 instruction's typed semantic model."""

# Native runtime must preload declared libstdc++ before Z3 or Angr imports.
from extractor.runtime import load_shellcode
from extractor.extractor import extract


SOURCE = 0x400000
ADD_RAX_RBX = bytes.fromhex("4801d8")


def main() -> None:
    project = load_shellcode(ADD_RAX_RBX, SOURCE)
    print(extract(project, SOURCE).to_json())


if __name__ == "__main__":
    main()
