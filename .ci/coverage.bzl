"""Add coverage collection to the existing immutable Nix interpreter."""

def _coverage_entrypoint_impl(ctx):
    package = ctx.attr.package[DefaultInfo]
    entrypoints = [
        f
        for f in package.files.to_list()
        if f.path.endswith("/coverage/__main__.py")
    ]
    if len(entrypoints) != 1:
        fail("Expected the pinned coverage wheel to contain coverage/__main__.py")
    return [DefaultInfo(
        files = depset(entrypoints),
        runfiles = ctx.runfiles(transitive_files = package.files).merge(package.default_runfiles),
    )]

coverage_entrypoint = rule(
    implementation = _coverage_entrypoint_impl,
    attrs = {"package": attr.label(mandatory = True)},
)

def _coverage_runtime_impl(ctx):
    root = ctx.os.environ.get("IXYK_NIX_PYTHON_RUNTIME")
    if not root or not root.startswith("/nix/store/"):
        fail("Run coverage inside the pinned nix develop environment")
    ctx.file("BUILD.bazel", """
load("@rules_python//python:py_runtime.bzl", "py_runtime")
load("@rules_python//python:py_runtime_pair.bzl", "py_runtime_pair")
py_runtime(
    name = "runtime",
    interpreter_path = %r,
    interpreter_version_info = {"major": "3", "minor": "12", "micro": "13"},
    python_version = "PY3",
    coverage_tool = "@@//.ci:coverage_tool",
)
py_runtime_pair(name = "pair", py3_runtime = ":runtime")
toolchain(
    name = "toolchain",
    toolchain = ":pair",
    toolchain_type = "@rules_python//python:toolchain_type",
    target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    visibility = ["//visibility:public"],
)
""" % (root + "/bin/python3.12"))

coverage_runtime = repository_rule(
    implementation = _coverage_runtime_impl,
    environ = ["IXYK_NIX_PYTHON_RUNTIME"],
    local = True,
)
