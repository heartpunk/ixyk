"""Hermetic linking for Lake-declared Lean executable targets."""

load("//tools:lean_module.bzl", "LeanModuleInfo", "LeanNativeInfo")

LeanBinaryInfo = provider(
    doc = "A linked Lean executable and its explicit runtime metadata.",
    fields = {
        "launcher": "the Linux runtime-launcher File, or None on Darwin",
        "ordered_objects": "the ordered list of native object Files passed to the linker",
        "platform": "the stable execution-platform identity",
        "root_module": "the Lake-declared executable root module name",
        "raw_executable": "the untouched linked executable File under bin/",
        "runfiles": "the complete Runfiles object for the runtime entrypoint",
        "support_interpreter": "whether interpreter symbol support was requested",
        "toolchain_identity": "the stable Lean SDK/toolchain identity",
    },
)

_NON_EXPORT_FACET = "module.o"
_EXPORT_FACET = "module.o.export"

def _quote_rsp_arg(value):
    """Quote one argument for Clang's response-file parser."""
    if "\n" in value or "\r" in value:
        fail("lean_binary link arguments must not contain line breaks")
    return "\"{}\"".format(value.replace("\\", "\\\\").replace("\"", "\\\""))

def _merge_runfiles(ctx, direct_files, root_symlinks):
    runfiles = ctx.runfiles(
        files = ctx.files.data + direct_files,
        root_symlinks = root_symlinks,
    )
    for target in ctx.attr.data:
        if DefaultInfo in target:
            runfiles = runfiles.merge(target[DefaultInfo].default_runfiles)
    return runfiles

def _runtime_root_symlinks(toolchain):
    symlinks = {}
    for runtime_file in toolchain.runtime_files:
        runfile_path = "lean-sdk/" + runtime_file.logical_path
        if runfile_path in symlinks:
            fail("duplicate Lean SDK runtime runfile '{}'".format(runfile_path))
        symlinks[runfile_path] = runtime_file.file
    return symlinks

def _lean_binary_impl(ctx):
    if ctx.attr.shared_lean:
        fail("lean_binary does not yet support sharedLean")
    if not ctx.attr.output_name:
        fail("lean_binary output_name must be nonempty")
    if "/" in ctx.attr.output_name or "\\" in ctx.attr.output_name:
        fail("lean_binary output_name must be a file name, not a path")
    if not ctx.attr.root_module:
        fail("lean_binary root_module must be nonempty")
    if not ctx.attr.link_modules:
        fail("lean_binary requires a nonempty ordered link_modules plan")
    if len(ctx.attr.link_modules) != len(ctx.attr.link_facets):
        fail("lean_binary link_modules and link_facets must have equal lengths")

    toolchain = ctx.toolchains["//toolchains:lean_toolchain_type"]
    if toolchain.platform not in ["aarch64-darwin", "x86_64-linux"]:
        fail("lean_binary received unsupported platform '{}'".format(toolchain.platform))

    ordered_objects = []
    seen_modules = {}
    expected_facet = _EXPORT_FACET if ctx.attr.support_interpreter else _NON_EXPORT_FACET
    for index in range(len(ctx.attr.link_modules)):
        module = ctx.attr.link_modules[index]
        module_key = str(module.label)
        if module_key in seen_modules:
            fail("lean_binary link_modules contains duplicate target '{}'".format(module_key))
        seen_modules[module_key] = True

        native = module[LeanNativeInfo]
        facet = ctx.attr.link_facets[index]
        if facet != expected_facet:
            fail(
                "lean_binary support_interpreter={} requires facet '{}', got '{}' for '{}'".format(
                    ctx.attr.support_interpreter,
                    expected_facet,
                    facet,
                    module_key,
                ),
            )
        if facet == _NON_EXPORT_FACET:
            ordered_objects.append(native.object)
        elif facet == _EXPORT_FACET:
            ordered_objects.append(native.export_object)
        else:
            fail("lean_binary does not support native facet '{}'".format(facet))

    raw_executable = ctx.actions.declare_file("bin/{}".format(ctx.attr.output_name))
    response_file = ctx.actions.declare_file("link-rsp/{}.rsp".format(ctx.attr.output_name))
    response_args = (
        [obj.path for obj in ordered_objects] +
        ctx.attr.weak_link_args +
        ctx.attr.link_args +
        ["-L", toolchain.lean_lib_dir] +
        toolchain.cc_link_static_flags
    )
    ctx.actions.write(
        output = response_file,
        content = "\n".join([_quote_rsp_arg(arg) for arg in response_args]) + "\n",
    )

    action_env = {
        "HOME": "/nonexistent",
        "LEAN_BAZEL_PLATFORM": toolchain.platform,
        "LEAN_BAZEL_TOOLCHAIN_ID": toolchain.identity,
        "PATH": "",
        "TMPDIR": "/tmp",
    }
    if toolchain.platform == "aarch64-darwin":
        action_env["MACOSX_DEPLOYMENT_TARGET"] = "99.0"
    else:
        if toolchain.sysroot.startswith("/"):
            fail("Linux linker trampoline requires a relative declared SDK root")
        action_env["LEAN_BAZEL_LINKER_SDK_ROOT"] = toolchain.sysroot

    linker_tools = depset(
        direct = [
            toolchain.cc,
            toolchain.cc_runner,
            toolchain.identity_file,
            toolchain.linker,
        ],
        transitive = [toolchain.files],
    )
    link_direct_inputs = ordered_objects + [response_file, toolchain.identity_file]
    if ctx.file.freshness:
        link_direct_inputs.append(ctx.file.freshness)
    ctx.actions.run(
        arguments = toolchain.cc_runner_args + [
            "-B" + toolchain.linker.dirname + "/",
            "-o",
            raw_executable.path,
            "@" + response_file.path,
        ],
        env = action_env,
        executable = toolchain.cc_runner,
        inputs = depset(
            direct = link_direct_inputs,
            transitive = [toolchain.files],
        ),
        mnemonic = "LeanLink",
        outputs = [raw_executable],
        progress_message = "Linking Lean executable {}".format(ctx.attr.output_name),
        tools = linker_tools,
    )

    launcher = None
    runtime_entrypoint = raw_executable
    runtime_root_symlinks = {}
    default_files = [raw_executable]
    if toolchain.platform == "x86_64-linux":
        if not toolchain.binary_runner:
            fail("Linux lean_binary requires the declared runtime trampoline")
        launcher = ctx.actions.declare_file("runner/{}".format(ctx.attr.output_name))
        ctx.actions.symlink(
            output = launcher,
            target_file = toolchain.binary_runner,
            is_executable = True,
        )
        runtime_entrypoint = launcher
        runtime_root_symlinks = _runtime_root_symlinks(toolchain)
        runtime_root_symlinks["lean-binary/payload"] = raw_executable
        default_files.append(launcher)

    runfiles = _merge_runfiles(ctx, default_files, runtime_root_symlinks)
    default_info = DefaultInfo(
        executable = runtime_entrypoint,
        files = depset(default_files),
        runfiles = runfiles,
    )
    return [
        default_info,
        LeanBinaryInfo(
            launcher = launcher,
            ordered_objects = ordered_objects,
            platform = toolchain.platform,
            root_module = ctx.attr.root_module,
            raw_executable = raw_executable,
            runfiles = runfiles,
            support_interpreter = ctx.attr.support_interpreter,
            toolchain_identity = toolchain.identity,
        ),
    ]

lean_binary = rule(
    implementation = _lean_binary_impl,
    attrs = {
        "data": attr.label_list(allow_files = True),
        "freshness": attr.label(allow_single_file = True),
        "link_args": attr.string_list(),
        "link_facets": attr.string_list(),
        "link_modules": attr.label_list(
            providers = [[LeanModuleInfo, LeanNativeInfo]],
        ),
        "output_name": attr.string(mandatory = True),
        "root_module": attr.string(mandatory = True),
        "shared_lean": attr.bool(default = False),
        "support_interpreter": attr.bool(default = False),
        "weak_link_args": attr.string_list(),
    },
    executable = True,
    toolchains = ["//toolchains:lean_toolchain_type"],
)
