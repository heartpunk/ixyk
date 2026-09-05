# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Normalize either committed golden artifacts or Bazel acquisition outputs."""

import argparse
import json
from pathlib import Path

from inventory.golden import index_artifacts, load_cache, sha256


def live_cache(specifications: list[str]) -> dict:
    files = {}
    for specification in specifications:
        name, path = specification.split("=", 1)
        if Path(name).name != name or name in files:
            raise ValueError(f"invalid or duplicate artifact name: {name}")
        files[name] = Path(path).read_bytes()
    manifest = "".join(f"{sha256(files[name])}  {name}\n" for name in sorted(files))
    return index_artifacts(files, sha256(manifest.encode()), ".model.json", "live")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--golden-manifest", type=Path)
    inputs.add_argument("--artifact", action="append")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cache = (
        load_cache(args.golden_manifest.parent)
        if args.golden_manifest
        else live_cache(args.artifact)
    )
    args.output.write_text(json.dumps(cache, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
