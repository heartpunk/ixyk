from unittest.mock import patch
import runpy
from extractor import z3_runtime  # noqa: F401 -- preload native runtime
from antiunification.algebra import AlgebraError

with patch(
    "antiunification.many.antiunify_many",
    side_effect=AlgebraError("validation: forced AU failure"),
):
    runpy.run_path("guarded_benchmark.py", run_name="__main__")
