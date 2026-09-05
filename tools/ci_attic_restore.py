"""Restore non-upstream members of a published development closure without builds."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.error import HTTPError
from urllib.request import urlopen


UPSTREAM = "https://cache.nixos.org"
ATTIC = "http://abraxas.quetzal-celsius.ts.net:8080/ixyk-ci"


def validate_paths(raw):
    paths = json.loads(raw)
    if not isinstance(paths, list) or not paths:
        raise ValueError("published closure must be a nonempty path list")
    for path in paths:
        if not isinstance(path, str) or not re.fullmatch(
            r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+", path
        ):
            raise ValueError(f"invalid published store path: {path!r}")
    return sorted(set(paths))


def upstream_has(path):
    store_hash = Path(path).name[:32]
    try:
        with urlopen(f"{UPSTREAM}/{store_hash}.narinfo", timeout=30) as response:
            if response.status != 200:
                raise ValueError(f"unexpected upstream status: {response.status}")
            return True
    except HTTPError as error:
        if error.code == 404:
            error.close()
            return False
        raise


def restore(raw):
    paths = validate_paths(raw)
    with ThreadPoolExecutor(max_workers=8) as pool:
        upstream = list(pool.map(upstream_has, paths))
    targets = [path for path, cached in zip(paths, upstream) if not cached]
    if not targets:
        raise ValueError("no Attic-dependent paths in published closure")
    for path in targets:
        if Path(path).exists():
            raise ValueError(f"restore is not cold: {path}")
    print(
        f"Restoring {len(targets)} Attic-dependent paths; {sum(upstream)} upstream paths need no separate check",
        flush=True,
    )
    for path in targets:
        print(path, flush=True)
    # Upstream references remain available; no upstream-only roots are tested.
    subprocess.run(
        [
            "nix-store",
            "--realise",
            *targets,
            "--max-jobs",
            "0",
            "--option",
            "builders",
            "",
            "--option",
            "substituters",
            f"{ATTIC} {UPSTREAM}",
        ],
        check=True,
    )
    print("Full Attic development closure restore verified", flush=True)


if __name__ == "__main__":
    restore(os.environ["PUBLISHED_CLOSURE"])
