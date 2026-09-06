# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run the real benchmark as a REAPI action and retain its output artifacts."""

import os
import sys

from extractor.evidence_benchmark import main

if __name__ == "__main__":
    result = main(
        [*sys.argv[1:], "--output-dir", os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]]
    )
    assert all(
        case["executions"] == result["samples_per_opcode"] for case in result["cases"]
    ), result
