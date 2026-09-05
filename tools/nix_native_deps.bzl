# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Expose the Nix-selected Linux C++ runtime as a declared Bazel input."""

_ROOT_ENV = "IXYK_NIX_LIBSTDCXX_ROOT"
_XED_ENV = "IXYK_NIX_XED_ROOT"

def _repository_impl(repository_ctx):
    root = repository_ctx.os.environ.get(_ROOT_ENV)
    if not root or not root.startswith("/nix/store/"):
        fail("{} must identify an immutable Nix store output".format(_ROOT_ENV))
    library = repository_ctx.path(root + "/lib/libstdc++.so.6")
    if not library.exists:
        fail("{} does not contain lib/libstdc++.so.6".format(root))
    repository_ctx.symlink(library, "lib/libstdc++.so.6")
    xed_root = repository_ctx.os.environ.get(_XED_ENV)
    if not xed_root or not xed_root.startswith("/nix/store/"):
        fail("{} must identify an immutable Nix store output".format(_XED_ENV))
    repository_ctx.symlink(xed_root + "/include", "include")
    repository_ctx.symlink(xed_root + "/lib/libxed.a", "lib/libxed.a")
    repository_ctx.symlink(xed_root + "/lib/libxed-enc2-m64-a64.a", "lib/libxed-enc2-m64-a64.a")
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

filegroup(
    name = "libstdcxx",
    srcs = ["lib/libstdc++.so.6"],
)
""",
    )

_repository = repository_rule(
    implementation = _repository_impl,
    configure = True,
    environ = [_ROOT_ENV, _XED_ENV],
    local = True,
)

def _extension_impl(_module_ctx):
    _repository(name = "nix_native_deps")

nix_native_deps = module_extension(
    implementation = _extension_impl,
    arch_dependent = True,
    os_dependent = True,
)
