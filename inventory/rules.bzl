# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run inventory tools directly, with all executables declared as inputs."""

def _cache_impl(ctx):
    args = ctx.actions.args()
    args.add("--output", ctx.outputs.out)
    inputs = list(ctx.files.srcs)
    tools = [ctx.attr._index[DefaultInfo].files_to_run]
    env = {"PATH": ctx.toolchains["@rules_python//python:toolchain_type"].py3_runtime.interpreter_path.rsplit("/", 1)[0]}
    if ctx.file.manifest:
        inputs.append(ctx.file.manifest)
        args.add("--golden-manifest", ctx.file.manifest)
        tools.append(ctx.executable._zstd)
        env["IXYK_ZSTD"] = ctx.executable._zstd.path
    else:
        for source in ctx.files.srcs:
            args.add("--artifact", source.basename + "=" + source.path)
    ctx.actions.run(executable = ctx.executable._index, arguments = [args], inputs = inputs, tools = tools, outputs = [ctx.outputs.out], env = env, mnemonic = "InventoryCache")
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

cache_index = rule(
    implementation = _cache_impl,
    toolchains = ["@rules_python//python:toolchain_type"],
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "manifest": attr.label(allow_single_file = True),
        "out": attr.output(mandatory = True),
        "_index": attr.label(default = "//inventory:index_cache", executable = True, cfg = "exec"),
        "_zstd": attr.label(default = "@inventory_zstd//:bin/zstd", allow_single_file = True, executable = True, cfg = "exec"),
    },
)

def _report_impl(ctx):
    args = ctx.actions.args()
    args.add("--cache-index", ctx.file.cache)
    args.add("--inventory", ctx.file.inventory)
    args.add("--output", ctx.outputs.out)
    ctx.actions.run(
        executable = ctx.executable._report,
        arguments = [args],
        inputs = [ctx.file.cache, ctx.file.inventory],
        tools = [ctx.attr._report[DefaultInfo].files_to_run, ctx.executable._souffle],
        outputs = [ctx.outputs.out],
        env = {"IXYK_SOUFFLE": ctx.executable._souffle.path, "PATH": ctx.toolchains["@rules_python//python:toolchain_type"].py3_runtime.interpreter_path.rsplit("/", 1)[0]},
        mnemonic = "InventoryReport",
    )
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

availability_report = rule(
    implementation = _report_impl,
    toolchains = ["@rules_python//python:toolchain_type"],
    attrs = {
        "cache": attr.label(allow_single_file = True, mandatory = True),
        "inventory": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.output(mandatory = True),
        "_report": attr.label(default = "//inventory:report", executable = True, cfg = "exec"),
        "_souffle": attr.label(default = "@inventory_souffle//:bin/souffle", allow_single_file = True, executable = True, cfg = "exec"),
    },
)
