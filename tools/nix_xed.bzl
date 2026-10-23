# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Expose IXYK's pinned Linux XED ENC2 libraries to its Bazel targets."""

_XED_ENV = "IXYK_NIX_XED_ROOT"

def _repository_impl(repository_ctx):
    if repository_ctx.os.name != "linux" or repository_ctx.os.arch not in ["amd64", "x86_64"]:
        fail("XED ENC2 validation requires a Linux x86-64 client and executor")
    root = repository_ctx.os.environ.get(_XED_ENV)
    if not root or not root.startswith("/nix/store/"):
        fail("{} must identify an immutable Nix store output".format(_XED_ENV))
    repository_ctx.symlink(root + "/include", "include")
    repository_ctx.symlink(root + "/lib/libxed.a", "lib/libxed.a")
    repository_ctx.symlink(root + "/lib/libxed-enc2-m64-a64.a", "lib/libxed-enc2-m64-a64.a")
    repository_ctx.file(
        "BUILD.bazel",
        """load("@rules_cc//cc:cc_import.bzl", "cc_import")
package(default_visibility = ["//visibility:public"])

cc_import(
    name = "xed",
    hdrs = glob(["include/xed/*.h"]),
    includes = ["include"],
    static_library = "lib/libxed.a",
)

cc_import(
    name = "xed_enc2",
    static_library = "lib/libxed-enc2-m64-a64.a",
    deps = [":xed"],
)
""",
    )

nix_xed_repository = repository_rule(
    implementation = _repository_impl,
    configure = True,
    environ = [_XED_ENV],
    local = True,
)
