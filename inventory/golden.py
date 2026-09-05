# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read the committed golden model cache; never acquire or synthesize models."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess

from extractor.artifact import InstructionModel
from inventory.souffle import reachable as reachable
from inventory.souffle import summaries as query_summaries


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_cache(directory: Path) -> dict:
    manifest = (directory / "MANIFEST.sha256").read_bytes()
    files = {}
    for line in manifest.decode().splitlines():
        expected, name = line.split("  ", 1)
        if Path(name).name != name or name in files:
            raise ValueError(f"invalid or duplicate manifest entry: {name}")
        content = (directory / name).read_bytes()
        if sha256(content) != expected:
            raise ValueError(f"golden checksum mismatch: {name}")
        files[name] = content
    acquisitions = sorted(directory.glob("*.acquisition.json"))
    expected_files = {
        name
        for path in acquisitions
        for name in (
            path.name,
            path.name.replace(".acquisition.json", ".model.json.zst"),
        )
    }
    if not acquisitions or expected_files != set(files):
        raise ValueError(
            "golden manifest must cover exactly the acquisition/model pairs"
        )
    return index_artifacts(files, sha256(manifest), ".model.json.zst", "golden")


def index_artifacts(
    files: dict[str, bytes], manifest_digest: str, model_suffix: str, origin: str
) -> dict:
    """Normalize recorded acquisition/model pairs without invoking extraction."""
    acquisitions = sorted(name for name in files if name.endswith(".acquisition.json"))
    expected = {
        name
        for acquisition in acquisitions
        for name in (
            acquisition,
            acquisition.replace(".acquisition.json", model_suffix),
        )
    }
    if not acquisitions or set(files) != expected:
        raise ValueError("expected exactly one model per acquisition")
    models = defaultdict(list)
    unavailable = {}
    for name in acquisitions:
        acquisition = json.loads(files[name])
        if acquisition["schema"] != "ixyk.instruction_acquisition.v1":
            raise ValueError(f"unknown acquisition schema: {name}")
        instruction = bytes.fromhex(acquisition["instruction_hex"])
        if not 1 <= len(instruction) <= 15:
            raise ValueError(f"invalid instruction bytes: {name}")
        key = instruction.hex()
        model_name = name.replace(".acquisition.json", model_suffix)
        raw = files[model_name]
        if model_suffix.endswith(".zst"):
            raw = subprocess.run(
                [os.environ.get("IXYK_ZSTD", "zstd"), "-dc"],
                input=raw,
                capture_output=True,
                check=True,
            ).stdout
        value = json.loads(raw)
        if acquisition["status"] == "pass":
            model = InstructionModel.from_data(value)
            models[key].append(
                {
                    "acquisition": name,
                    "model": model_name,
                    "artifact_sha256": sha256(files[model_name]),
                    **(
                        {"compressed_sha256": sha256(files[model_name])}
                        if model_suffix.endswith(".zst")
                        else {}
                    ),
                    "model_sha256": sha256(raw),
                    "source": model.source,
                }
            )
        else:
            if (
                acquisition["status"] not in ("unsupported", "acquisition_error")
                or value.get("schema") != "ixyk.unavailable_instruction_model.v1"
                or value.get("status") != acquisition["status"]
            ):
                raise ValueError(f"inconsistent unavailable artifact: {model_name}")
            unavailable[key] = {
                "status": acquisition["status"],
                "error": acquisition["error"],
            }
    return {
        "schema": "ixyk.instruction_cache_index.v1",
        "manifest_sha256": manifest_digest,
        "origin": origin,
        "models": dict(models),
        "unavailable": unavailable,
        "acquisitions": len(acquisitions),
    }


def report(inventory: dict, cache: dict) -> dict:
    if inventory.get("schema") != "ixyk.bochs_binary_inventory.v1":
        raise ValueError("unknown binary inventory schema")
    nodes = inventory["nodes"]
    root_sets = list(
        dict.fromkeys(tuple(target["roots"]) for target in inventory["targets"])
    )
    summaries = query_summaries(nodes, root_sets, cache["models"])
    available = []
    excluded = []
    for target in inventory["targets"]:
        roots = tuple(target["roots"])
        summary = summaries[roots]
        row = {
            "id": target["id"],
            "mnemonic": target["mnemonic"],
            "handlers": target["handlers"],
            "roots": list(roots),
            **summary,
        }
        reasons = []
        if target["unresolved_handlers"]:
            reasons.append("unresolved_handler")
            row["unresolved_handlers"] = target["unresolved_handlers"]
        if not roots or not summary["host_instruction_sites"]:
            reasons.append("no_host_code")
        if summary["unknown_transfers"]:
            reasons.append("unresolved_dependency")
        if summary["cache_miss_sites"]:
            reasons.append("golden_cache_miss")
        if summary["trivial_body"]:
            reasons.append("trivial_handler_body")
        if reasons:
            row["reasons"] = reasons
            excluded.append(row)
        else:
            available.append(row)
    groups = defaultdict(list)
    for target in available:
        groups[tuple(target["handlers"])].append(target["id"])
    cohorts = [
        {
            "handlers": list(handlers),
            "target_forms": sorted(targets),
            "count": len(targets),
        }
        for handlers, targets in groups.items()
    ]
    cohorts.sort(key=lambda item: (-item["count"], item["handlers"]))
    return {
        "schema": "ixyk.golden_transport_availability.v1",
        "source_revision": inventory["source_revision"],
        "elf_sha256": inventory["elf_sha256"],
        "cache_manifest_sha256": cache["manifest_sha256"],
        "cache_origin": cache.get("origin", "golden"),
        "cache_acquisitions": cache["acquisitions"],
        "cache_available_models": sum(map(len, cache["models"].values())),
        "match_contract": "exact instruction bytes; models retain their recorded source addresses",
        "qualification": "Cached host-model prerequisites only. Source-declared forms can include no-op handlers and disabled-feature stubs. Guest instruction support, address rebasing, guest-state mapping, composition, and target validation are not established.",
        "target_forms": len(inventory["targets"]),
        "cache_covered_forms": len(available),
        "excluded_forms": len(excluded),
        "exclusion_counts": dict(
            sorted(
                Counter(reason for row in excluded for reason in row["reasons"]).items()
            )
        ),
        "cohorts": cohorts,
        "available": available,
        "excluded": excluded,
        "cached_models": cache["models"],
        "cached_unavailable": cache["unavailable"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--cache-index", type=Path)
    inputs.add_argument(
        "--golden",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts/golden",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cache = (
        json.loads(args.cache_index.read_text())
        if args.cache_index
        else load_cache(args.golden)
    )
    value = report(json.loads(args.inventory.read_text()), cache)
    args.output.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: value[key]
                for key in (
                    "target_forms",
                    "cache_covered_forms",
                    "excluded_forms",
                    "exclusion_counts",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
