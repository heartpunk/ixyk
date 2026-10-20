"""Observe existing CI output before cleanup; never change a test result."""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import time
from pathlib import Path

# Preserve any interpreter-provided sitecustomize, including Nix's setup.
observer = Path(__file__).resolve().parent
search = [entry for entry in sys.path if Path(entry or ".").resolve() != observer]
original = importlib.machinery.PathFinder.find_spec("sitecustomize", search)
if original and original.origin and Path(original.origin).resolve() != Path(__file__).resolve():
    loader = importlib.machinery.SourceFileLoader("_ixyk_original_sitecustomize", original.origin)
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader)
    )
    loader.exec_module(module)

destination = os.environ.get("IXYK_CI_DIAGNOSTICS")
if destination:
    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    (output / f"observer-{os.getpid()}.json").write_text(json.dumps({
        "pid": os.getpid(),
        "executable": sys.executable,
        "base_executable": sys._base_executable,
        "python": sys.version,
        "original_sitecustomize": original.origin if original else None,
        "path": sys.path,
    }, indent=2) + "\n")

    def preserve(event, arguments):
        if event != "shutil.rmtree":
            return
        try:
            directory = Path(arguments[0])
            fuzz = directory / "fuzz.json"
            if not fuzz.is_file():
                return
            prefix = f"{os.getpid()}-{time.time_ns()}"
            sizes = {}
            for name in ("fuzz.json", "result.json", "model.json"):
                source = directory / name
                if source.is_file():
                    sizes[name] = source.stat().st_size
                    if sizes[name] <= 32 * 1024 * 1024:
                        shutil.copyfile(source, output / f"{prefix}-{name}")
            (output / f"{prefix}-sizes.json").write_text(json.dumps(sizes, indent=2) + "\n")
        except Exception as error:
            print(f"CI output observer: {error!r}", file=sys.stderr)

    sys.addaudithook(preserve)
