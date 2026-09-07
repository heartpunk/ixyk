import json
import pathlib
from unittest.mock import patch
from extractor import z3_runtime  # noqa: F401 -- preload native runtime
from extractor import acquire_cli, fuzz_cli
from extractor.extractor import extract

root = pathlib.Path("cli-results")
root.mkdir(exist_ok=True)
for name, code, fallback in [
    ("ADD", "4801d8", False),
    ("ADD-fallback", "4801d8", True),
]:
    out = root / name
    out.mkdir(exist_ok=True)

    def force_failure(project, source, **kw):
        from antiunification.algebra import AlgebraError

        with patch(
            "antiunification.many.antiunify_many",
            side_effect=AlgebraError("forced fallback validation"),
        ):
            return extract(project, source, **kw)

    with patch.object(acquire_cli, "extract", force_failure if fallback else extract):
        acquire_cli.main(
            [
                "--instruction-hex",
                code,
                "--model-output",
                str(out / "model.json"),
                "--result-output",
                str(out / "acquisition.json"),
            ]
        )
    acquisition = json.loads((out / "acquisition.json").read_text())
    assert acquisition["model_route"] == ("direct" if fallback else "generalized"), (
        acquisition
    )
    fuzz_cli.main(
        [
            "--instruction-hex",
            code,
            "--acquisition",
            str(out / "acquisition.json"),
            "--model",
            str(out / "model.json"),
            "--examples",
            "101",
            "--seconds",
            "60",
            "--output",
            str(out / "report.json"),
        ]
    )
    report = json.loads((out / "report.json").read_text())
    assert report["executions"] == 101, report
    assert len(report["prepared_models"]) == (
        len(acquisition["retained_models"]) if fallback else 1
    ), report
    assert report["fallback_allocations"] == report["planned_fallback_allocations"]
    assert report["acquisition_findings"] == len(acquisition["findings"])
    print(name, report["executions"], report["fallback_allocations"], flush=True)
