# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""One independently runnable semantic-regression target per instruction."""

load("@rules_python//python:defs.bzl", "py_test")

def semantic_regression_test(name, instruction_hex, args = []):
    py_test(
        name = name,
        size = "small",
        srcs = ["semantic_regression_test.py"],
        args = ["--instruction-hex", instruction_hex] + args,
        data = ["@nix_native_deps//:libstdcxx"],
        env = {
            "GHOT_LIBSTDCXX_RLOCATION": "$(rlocationpath @nix_native_deps//:libstdcxx)",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        },
        main = "semantic_regression_test.py",
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
        deps = [
            ":extractor",
            ":fuzzer",
            ":runtime",
        ],
    )
