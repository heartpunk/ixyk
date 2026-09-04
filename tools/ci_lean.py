"""Exercise the Lean artifact CLI on the committed corpus and malformed models."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile


def read_model(path: Path) -> dict:
    data = (
        subprocess.check_output(["zstd", "-dc", str(path)])
        if path.suffix == ".zst"
        else path.read_bytes()
    )
    return json.loads(data)


def check(workspace: Path) -> None:
    directory = workspace / "artifacts/golden"
    paths = sorted(directory.glob("*.model.json")) + sorted(
        directory.glob("*.model.json.zst")
    )
    if not paths:
        raise ValueError("no golden models found")
    manifest_names = {
        line.split()[1]
        for line in (directory / "MANIFEST.sha256").read_text().splitlines()
    }
    expected = {
        name
        for name in manifest_names
        if name.endswith((".model.json", ".model.json.zst"))
    }
    if {p.name for p in paths} != expected:
        raise ValueError("model files differ from the manifest")
    binary = workspace / ".lake/build/bin/ixyk-golden-check"
    subprocess.run([str(binary), *map(str, paths)], check=True)
    models = [read_model(path) for path in paths]
    executable = [
        model for model in models if model.get("schema") == "ixyk.qf_abv.instruction.v1"
    ]
    unavailable = [
        model
        for model in models
        if model.get("schema") == "ixyk.unavailable_instruction_model.v1"
    ]
    if not executable or len(executable) + len(unavailable) != len(models):
        raise ValueError("unexpected corpus classification")
    print(
        f"Imported {len(executable)} executable models and {len(unavailable)} unavailable artifacts",
        flush=True,
    )
    source = executable[0]
    bad_sort = copy.deepcopy(source)
    bad_sort["steps"][0]["guard"] = {
        "op": "bool_lit",
        "sort": {"kind": "bv", "width": 8},
        "value": True,
    }
    missing_update = copy.deepcopy(source)
    missing_update["steps"][0]["simultaneous_update"].pop()
    duplicate = copy.deepcopy(source)
    duplicate["declarations"].append(copy.deepcopy(duplicate["declarations"][0]))
    mirrored_pc = copy.deepcopy(source)
    mirrored_pc["steps"][0]["mirrored_pc"] = {
        "op": "bool_lit",
        "sort": {"kind": "bool"},
        "value": True,
    }
    with tempfile.TemporaryDirectory(prefix="ixyk-lean-rejections-") as temporary:
        for name, model in [
            ("wrong-sort", bad_sort),
            ("missing-update", missing_update),
            ("duplicate-declaration", duplicate),
            ("mirrored-pc", mirrored_pc),
            ("unknown-schema", {"schema": "not-an-ixyk-model"}),
        ]:
            path = Path(temporary) / f"{name}.json"
            path.write_text(json.dumps(model))
            result = subprocess.run(
                [str(binary), str(path)], capture_output=True, text=True
            )
            if result.returncode != 1:
                raise ValueError(
                    f"{name}: expected rejection (exit 1), got {result.returncode}: {result.stderr}"
                )
            print(f"Rejected {name}", flush=True)


if __name__ == "__main__":
    check(Path.cwd())
