# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""The extractor CLI writes a reusable typed model artifact."""

from tempfile import TemporaryDirectory
from pathlib import Path

from extractor.artifact import InstructionModel
from extractor.extract_cli import DEFAULT_SOURCE, main


def test_writes_model_file() -> None:
    with TemporaryDirectory() as directory:
        output = Path(directory) / "add.json"
        main(("--instruction-hex", "4801d8", "--output", str(output)))
        model = InstructionModel.from_json(output.read_text(encoding="utf-8"))
    assert model.source == DEFAULT_SOURCE
    assert model.steps


if __name__ == "__main__":
    test_writes_model_file()
