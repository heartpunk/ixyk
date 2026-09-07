import os
import pathlib
import sys
import runpy

base = pathlib.Path.home() / "workspaces/ixyk-perf"
root = pathlib.Path(__file__).resolve().parent
rf = base / "runtime/python.runfiles"
os.environ["RUNFILES_DIR"] = str(base / "ixyk-small-probe-20260906/runfiles")
sys.path[:0] = (
    [str(root / "source"), str(base / "ixyk-small-probe-20260906/wheels")]
    + [str(p / "site-packages") for p in sorted(rf.glob("rules_python++pip+*"))]
    + [str(rf / "ixyk_vendored_arpy+"), str(rf / "ixyk_vendored_mulpyplexer+")]
)
os.environ["PYTHONPATH"] = os.pathsep.join(sys.path)
module = sys.argv.pop(1)
if module == "pytest":
    from extractor import z3_runtime  # noqa: F401 -- preload native runtime
    import pytest

    raise SystemExit(pytest.main(sys.argv[1:]))
runpy.run_path(module, run_name="__main__")
