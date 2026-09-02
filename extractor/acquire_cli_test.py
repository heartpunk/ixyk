"""Acquisition emits exact models or explicit fail-closed artifacts."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from extractor.acquire_cli import main
from extractor.artifact import InstructionModel


def _acquire(instruction_hex: str, directory: Path) -> tuple[Path, dict[str, object]]:
    model, result = directory / "model.json", directory / "result.json"
    main(
        (
            "--instruction-hex",
            instruction_hex,
            "--model-output",
            str(model),
            "--result-output",
            str(result),
        )
    )
    raw = cast(object, json.loads(result.read_text(encoding="utf-8")))
    if not isinstance(raw, dict):
        raise AssertionError("acquisition result is not an object")
    return model, cast(dict[str, object], raw)


def main_test() -> None:
    with TemporaryDirectory() as temporary:
        directory = Path(temporary)
        scalar_model, scalar = _acquire("4801d8", directory)
        assert scalar["status"] == "pass"
        _ = InstructionModel.from_json(scalar_model.read_text(encoding="utf-8"))

        vector_model, vector = _acquire("660f6ec0", directory)
        assert vector["status"] == "unsupported"
        unavailable = cast(object, json.loads(vector_model.read_text(encoding="utf-8")))
        if not isinstance(unavailable, dict):
            raise AssertionError("unavailable model is not an object")
        assert unavailable["schema"] == "ixyk.unavailable_instruction_model.v1"


if __name__ == "__main__":
    main_test()
