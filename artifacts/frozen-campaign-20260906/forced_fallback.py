import runpy
from unittest.mock import patch

from antiunification.algebra import AlgebraError
from extractor import z3_runtime  # noqa: F401 -- preload native runtime

with patch(
    "antiunification.many.antiunify_many",
    side_effect=AlgebraError("validation: forced AU failure"),
):
    runpy.run_path("guarded_benchmark.py", run_name="__main__")
