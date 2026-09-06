import subprocess
import sys
import pathlib
import json

root = pathlib.Path(__file__).resolve().parent
cases = [
    ("ADD", "4801d8"),
    ("JE", "7400"),
    ("LEA", "488d444b08"),
    ("MOVSD", "f20f10c1"),
]
phase = sys.argv[1]
if phase == "baseline":
    jobs = [
        ("baseline", "yes", "p", name, code, mode)
        for name, code in cases
        for mode in ["off", "json"]
    ]
    jobs += [
        ("baseline", "no", f"r{repeat}", name, code, mode)
        for repeat in [1, 2]
        for name, code in cases
        for mode in ["off", "json"]
    ]
else:
    jobs = [
        ("cache", "no", f"r{repeat}", name, code, mode)
        for repeat in [1, 2]
        for name, code in cases
        for mode in ["off", "json"]
    ]
for variant, profiled, rep, name, code, mode in jobs:
    label = f"{variant}-{rep}-{name}-{mode}"
    if (root / "results" / label / "result.json").exists():
        continue
    result = subprocess.run(
        [
            sys.executable,
            str(root / "probe.py"),
            mode,
            name,
            code,
            variant,
            profiled,
            label,
        ]
    )
    if result.returncode:
        sys.exit(result.returncode)
print(json.dumps(dict(event="batch_done", phase=phase)), flush=True)
