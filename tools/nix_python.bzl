# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Select the immutable Python runtime supplied by the development environment."""

load("@rules_python//python/local_toolchains:repos.bzl", "local_runtime_repo", "local_runtime_toolchains_repo")

def _extension_impl(module_ctx):
    root = module_ctx.getenv("IXYK_NIX_PYTHON_RUNTIME")
    if not root or not root.startswith("/nix/store/"):
        fail("IXYK_NIX_PYTHON_RUNTIME must identify the Nix Python runtime; run nix develop")
    local_runtime_repo(
        name = "nix_python_3_12",
        interpreter_path = root + "/bin/python3.12",
        on_failure = "fail",
    )
    local_runtime_toolchains_repo(
        name = "nix_python_toolchains",
        runtimes = ["nix_python_3_12"],
        target_compatible_with = {
            "nix_python_3_12": ["HOST_CONSTRAINTS"],
        },
    )

nix_python = module_extension(
    implementation = _extension_impl,
    arch_dependent = True,
    os_dependent = True,
)
