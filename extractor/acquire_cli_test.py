"""Acquisition emits exact models or explicit fail-closed artifacts."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from extractor.acquire_cli import main
from extractor.artifact import InstructionModel
from extractor.fuzz_cli import main as fuzz_main


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
        scalar_fuzz = directory / "scalar-fuzz.json"
        fuzz_main(
            (
                "--acquisition",
                str(directory / "result.json"),
                "--model",
                str(scalar_model),
                "--instruction-hex",
                "4801d8",
                "--examples",
                "10",
                "--output",
                str(scalar_fuzz),
            )
        )
        scalar_fuzz_result = cast(
            object, json.loads(scalar_fuzz.read_text(encoding="utf-8"))
        )
        assert isinstance(scalar_fuzz_result, dict)
        assert scalar_fuzz_result["status"] == "pass"

        vector_model, vector = _acquire("660f6ec0", directory)
        assert vector["status"] == "unsupported"
        unavailable = cast(object, json.loads(vector_model.read_text(encoding="utf-8")))
        if not isinstance(unavailable, dict):
            raise AssertionError("unavailable model is not an object")
        assert unavailable["schema"] == "ixyk.unavailable_instruction_model.v1"
        vector_fuzz = directory / "vector-fuzz.json"
        fuzz_main(
            (
                "--acquisition",
                str(directory / "result.json"),
                "--model",
                str(vector_model),
                "--instruction-hex",
                "660f6ec0",
                "--examples",
                "10",
                "--output",
                str(vector_fuzz),
            )
        )
        vector_fuzz_result = cast(
            object, json.loads(vector_fuzz.read_text(encoding="utf-8"))
        )
        assert isinstance(vector_fuzz_result, dict)
        assert vector_fuzz_result["status"] == "unsupported"


if __name__ == "__main__":
    main_test()
