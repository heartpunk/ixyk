"""Check committed corpus integrity without regenerating or fuzzing models."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def _read_json(path: Path):
    contents = (
        subprocess.check_output(["zstd", "-dc", str(path)])
        if path.suffix == ".zst"
        else path.read_bytes()
    )
    return json.loads(contents)


def verify(workspace: Path) -> dict[str, int]:
    directory = workspace / "artifacts/golden"
    probes = json.loads((workspace / "catalog/x86_64_probes.json").read_text())[
        "probes"
    ]
    by_stem = {f"{p['rank']}_{p['name'].lower()}": p for p in probes}
    compressed = list(directory.glob("*.model.json.zst"))
    acquisition_suffix = (
        "acquisition.json.zst"
        if any(directory.glob("*.acquisition.json.zst"))
        else "acquisition.json"
    )
    # Support the existing five-example corpus until the complete-corpus PR lands.
    stems = (
        set(by_stem)
        if compressed
        else {"2_add", "12_ret", "28_mulsd", "36_pxor", "65_int3"}
    )
    suffixes = (
        (acquisition_suffix, "model.json.zst")
        if compressed
        else ("acquisition.json", "model.json", "fuzz-10000.json")
    )
    expected = {f"{stem}.{suffix}" for stem in stems for suffix in suffixes}
    manifest = {}
    for line in (directory / "MANIFEST.sha256").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if match is None or match[2] in manifest:
            raise ValueError("invalid or duplicate manifest entry")
        manifest[match[2]] = match[1]
    if set(manifest) != expected:
        raise ValueError("manifest does not contain the exact expected corpus")
    actual = {
        p.name
        for p in directory.iterdir()
        if p.name not in {"README.md", "MANIFEST.sha256"}
    }
    if actual != expected:
        raise ValueError("missing or unexpected corpus files")
    for name, digest in manifest.items():
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"invalid artifact or digest: {name}")
    counts = {"pass": 0, "unsupported": 0, "acquisition_error": 0}
    for stem in sorted(stems):
        acquisition = _read_json(directory / f"{stem}.{acquisition_suffix}")
        status = acquisition["status"]
        if (
            acquisition["schema"] != "ixyk.instruction_acquisition.v1"
            or status not in counts
        ):
            raise ValueError(f"invalid acquisition: {stem}")
        if acquisition["instruction_hex"] != by_stem[stem]["bytes"]:
            raise ValueError(f"instruction identity mismatch: {stem}")
        counts[status] += 1
        model_suffix = "model.json.zst" if compressed else "model.json"
        model = _read_json(directory / f"{stem}.{model_suffix}")
        if status == "pass" or acquisition.get("model_route") == "direct":
            if (
                model["schema"] != "ixyk.qf_abv.instruction.v1"
                or not model.get("steps")
                or not model.get("declarations")
            ):
                raise ValueError(f"missing executable model: {stem}")
            if status != "pass" and not any(
                item.get("instruction_hex") == acquisition["instruction_hex"]
                and item.get("model") == model
                for item in acquisition.get("retained_models", [])
            ):
                raise ValueError(f"direct model is not retained in acquisition: {stem}")
        elif (
            model.get("schema") != "ixyk.unavailable_instruction_model.v1"
            or model.get("status") != status
            or model.get("error") != acquisition.get("error")
        ):
            raise ValueError(f"unavailable model disagrees with acquisition: {stem}")
        if not compressed:
            report = json.loads((directory / f"{stem}.fuzz-10000.json").read_text())
            if (
                report.get("schema") != "ixyk.differential_fuzz.v1"
                or report.get("instruction_hex") != by_stem[stem]["bytes"]
                or report.get("examples_requested") != 10000
            ):
                raise ValueError(f"invalid fuzz report identity: {stem}")
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(json.dumps(verify(args.workspace), sort_keys=True))
