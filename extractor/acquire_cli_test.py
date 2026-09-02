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


def _fuzz(
    instruction_hex: str, model: Path, directory: Path
) -> dict[str, object]:
    output = directory / "fuzz.json"
    fuzz_main(
        (
            "--acquisition",
            str(directory / "result.json"),
            "--model",
            str(model),
            "--instruction-hex",
            instruction_hex,
            "--examples",
            "10",
            "--output",
            str(output),
        )
    )
    raw = cast(object, json.loads(output.read_text(encoding="utf-8")))
    if not isinstance(raw, dict):
        raise AssertionError("fuzz result is not an object")
    return cast(dict[str, object], raw)


def main_test() -> None:
    with TemporaryDirectory() as temporary:
        directory = Path(temporary)
        scalar_model, scalar = _acquire("4801d8", directory)
        assert scalar["status"] == "pass"
        _ = InstructionModel.from_json(scalar_model.read_text(encoding="utf-8"))
        assert _fuzz("4801d8", scalar_model, directory)["status"] == "pass"

        vector_model, vector = _acquire("660f6ec0", directory)
        assert vector["status"] == "pass"
        _ = InstructionModel.from_json(vector_model.read_text(encoding="utf-8"))
        assert _fuzz("660f6ec0", vector_model, directory)["status"] == "pass"

        fp_model, fp = _acquire("f20f58c1", directory)
        assert fp["status"] == "unsupported"
        unavailable = cast(object, json.loads(fp_model.read_text(encoding="utf-8")))
        if not isinstance(unavailable, dict):
            raise AssertionError("unavailable model is not an object")
        assert unavailable["schema"] == "ixyk.unavailable_instruction_model.v1"
        assert _fuzz("f20f58c1", fp_model, directory)["status"] == "unsupported"

        avx_model, avx = _acquire("c5f358c2", directory)
        assert avx["status"] == "unsupported"
        assert _fuzz("c5f358c2", avx_model, directory)["status"] == "unsupported"


if __name__ == "__main__":
    main_test()
