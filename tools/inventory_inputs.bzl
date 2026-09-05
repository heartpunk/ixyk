# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Declare cached Nix inventory data and decompression tools as Bazel inputs."""

def _input_impl(ctx):
    root = ctx.os.environ.get(ctx.attr.environment)
    if not root or not root.startswith("/nix/store/"):
        fail("%s must identify an immutable Nix output" % ctx.attr.environment)
    source_path = "bin/.souffle-wrapped" if ctx.attr.environment == "IXYK_NIX_SOUFFLE_ROOT" else ctx.attr.path
    source = ctx.path(root + "/" + source_path)
    if not source.exists:
        fail("missing Nix input: %s" % source)
    ctx.symlink(source, ctx.attr.path)
    ctx.file("BUILD.bazel", "exports_files([%s], visibility = [\"//visibility:public\"])\n" % json.encode(ctx.attr.path))

_input = repository_rule(
    implementation = _input_impl,
    attrs = {"environment": attr.string(), "path": attr.string()},
    environ = ["IXYK_BOCHS_INVENTORY_ROOT", "IXYK_NIX_ZSTD_ROOT", "IXYK_NIX_SOUFFLE_ROOT"],
    local = True,
    configure = True,
)

def _extension_impl(_ctx):
    _input(name = "bochs_inventory", environment = "IXYK_BOCHS_INVENTORY_ROOT", path = "inventory.json")
    _input(name = "inventory_zstd", environment = "IXYK_NIX_ZSTD_ROOT", path = "bin/zstd")

    _input(name = "inventory_souffle", environment = "IXYK_NIX_SOUFFLE_ROOT", path = "bin/souffle")

inventory_inputs = module_extension(implementation = _extension_impl)
