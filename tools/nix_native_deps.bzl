"""Expose the Nix-selected Linux C++ runtime as a declared Bazel input."""

_ROOT_ENV = "IXYK_NIX_LIBSTDCXX_ROOT"

def _repository_impl(repository_ctx):
    root = repository_ctx.os.environ.get(_ROOT_ENV)
    if not root or not root.startswith("/nix/store/"):
        fail("{} must identify an immutable Nix store output".format(_ROOT_ENV))
    library = repository_ctx.path(root + "/lib/libstdc++.so.6")
    if not library.exists:
        fail("{} does not contain lib/libstdc++.so.6".format(root))
    repository_ctx.symlink(library, "lib/libstdc++.so.6")
    repository_ctx.file(
        "BUILD.bazel",
        """package(default_visibility = ["//visibility:public"])

filegroup(
    name = "libstdcxx",
    srcs = ["lib/libstdc++.so.6"],
)
""",
    )

_repository = repository_rule(
    implementation = _repository_impl,
    configure = True,
    environ = [_ROOT_ENV],
    local = True,
)

def _extension_impl(_module_ctx):
    _repository(name = "nix_native_deps")

nix_native_deps = module_extension(
    implementation = _extension_impl,
    arch_dependent = True,
    os_dependent = True,
)
