# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""A fresh fuzz process must not rely on its caller preloading native libraries."""

import os
import subprocess
import sys


def main():
    # No project imports in this entrypoint: the child's first project import
    # must be fuzz_runner, both here and when multiprocessing unpickles _worker.
    script = """
from extractor.fuzz_runner import run_bounded
from extractor.extractor import _extract_concrete
from extractor.runtime import load_shellcode

if __name__ == '__main__':
    code = bytes.fromhex('4801d8')
    model = _extract_concrete(load_shellcode(code, 0x400000), 0x400000)
    report = run_bounded(model.to_json(), code, 30, examples=1, stage='discover')
    assert report['status'] == 'pass', report
    assert report['processing'] == 'complete', report
    assert report['executions'] == 1, report
"""
    subprocess.run(
        [sys.executable, "-P", "-c", script],
        env=os.environ | {"PYTHONPATH": os.pathsep.join(sys.path)},
        check=True,
        timeout=45,
    )


if __name__ == "__main__":
    main()
