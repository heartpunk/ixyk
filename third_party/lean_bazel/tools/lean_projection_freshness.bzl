"""Hermetic regeneration and exact verification of Lake-owned Bazel projections."""

load("//tools:lean_binary.bzl", "LeanBinaryInfo")

LeanProjectionFreshnessInfo = provider(
    doc = "Evidence produced by a successful mandatory projection-freshness check.",
    fields = {
        "metadata": "deterministic projection verification metadata File",
        "regenerated_manifest": "freshly exported Lake-authority manifest File",
        "regenerated_projection": "freshly rendered Bazel projection File",
        "stamp": "fixed success stamp File",
    },
)

_SUPPORTED_PLATFORMS = ["aarch64-darwin", "x86_64-linux"]

def _fail_control_characters(value, description):
    if "\t" in value or "\n" in value or "\r" in value:
        fail("{} must not contain tab or line-break characters".format(description))

def _validate_normalized_relative_path(path, description):
    _fail_control_characters(path, description)
    if not path or path.startswith("/") or "\\" in path:
        fail("{} must be a nonempty normalized relative path, got '{}'".format(description, path))
    for component in path.split("/"):
        if not component or component == "." or component == "..":
            fail("{} must be a nonempty normalized relative path, got '{}'".format(description, path))

def _logical_path_in_package(file, package, description):
    short_path = file.short_path
    _validate_normalized_relative_path(short_path, "{} short path".format(description))
    if package:
        prefix = package + "/"
        if not short_path.startswith(prefix):
            fail(
                "{} '{}' is not strictly beneath Bazel package '{}'".format(
                    description,
                    short_path,
                    package,
                ),
            )
        logical_path = short_path[len(prefix):]
    else:
        logical_path = short_path
    _validate_normalized_relative_path(logical_path, "{} logical path".format(description))
    return logical_path

def _files_to_run(target, description):
    if DefaultInfo not in target:
        fail("{} must provide DefaultInfo".format(description))
    files_to_run = target[DefaultInfo].files_to_run
    if files_to_run == None or files_to_run.executable == None:
        fail("{} must provide an executable FilesToRunProvider".format(description))
    return files_to_run

def _revision_sources(files, description):
    source_by_name = {}
    for file in files:
        basename = file.basename
        _validate_normalized_relative_path(basename, "{} source basename".format(description))
        if "/" in basename:
            fail("{} source basename must be a file name".format(description))
        logical_name = "tools/" + basename
        if logical_name in source_by_name:
            fail("{} contains duplicate stable source name '{}'".format(description, logical_name))
        _fail_control_characters(file.path, "{} source physical path".format(description))
        source_by_name[logical_name] = file
    if not source_by_name:
        fail("{} must not be empty".format(description))
    return [(name, source_by_name[name]) for name in sorted(source_by_name.keys())]

def _lean_projection_freshness_impl(ctx):
    toolchain = ctx.toolchains["//toolchains:lean_toolchain_type"]
    if toolchain.platform not in _SUPPORTED_PLATFORMS:
        fail("lean_projection_freshness received unsupported platform '{}'".format(toolchain.platform))
    for value, description in [
        (toolchain.platform, "Lean platform"),
        (toolchain.identity, "Lean toolchain identity"),
        (toolchain.sysroot, "Lean SDK root"),
        (toolchain.lean_lib_dir, "Lean library directory"),
    ]:
        if not value:
            fail("{} must be nonempty".format(description))

    exporter = ctx.attr._exporter[LeanBinaryInfo]
    renderer = ctx.attr._renderer[LeanBinaryInfo]
    for binary, description in [
        (exporter, "projection exporter"),
        (renderer, "projection renderer"),
    ]:
        if binary.platform != toolchain.platform:
            fail("{} platform does not match the active Lean toolchain".format(description))
        if binary.toolchain_identity != toolchain.identity:
            fail("{} identity does not match the active Lean toolchain".format(description))
        if binary.raw_executable == None:
            fail("{} has no raw executable artifact".format(description))
    if not exporter.support_interpreter:
        fail("projection exporter must be linked with interpreter support")

    exporter_files_to_run = _files_to_run(ctx.attr._exporter, "projection exporter")
    renderer_files_to_run = _files_to_run(ctx.attr._renderer, "projection renderer")
    export_runner_files_to_run = _files_to_run(ctx.attr._export_runner, "projection export runner")
    verifier_files_to_run = _files_to_run(ctx.attr._verifier, "projection verifier")

    committed_files = [
        (ctx.file.committed_manifest, "committed manifest"),
        (ctx.file.committed_projection, "committed projection"),
        (ctx.file.committed_lock, "committed projection lock"),
    ]
    committed_logical_paths = {}
    for file, description in committed_files:
        logical_path = _logical_path_in_package(file, ctx.label.package, description)
        if logical_path in committed_logical_paths:
            fail(
                "{} and {} have the same logical path '{}'".format(
                    committed_logical_paths[logical_path],
                    description,
                    logical_path,
                ),
            )
        committed_logical_paths[logical_path] = description

    if not ctx.files.workspace_inputs:
        fail("lean_projection_freshness workspace_inputs must not be empty")
    workspace_file_by_logical_path = {}
    for file in ctx.files.workspace_inputs:
        logical_path = _logical_path_in_package(file, ctx.label.package, "workspace input")
        if logical_path in committed_logical_paths:
            fail(
                "workspace input '{}' collides with {}".format(
                    logical_path,
                    committed_logical_paths[logical_path],
                ),
            )
        if logical_path in workspace_file_by_logical_path:
            fail("workspace_inputs contains duplicate logical path '{}'".format(logical_path))
        _fail_control_characters(file.path, "workspace input physical path")
        workspace_file_by_logical_path[logical_path] = file

    workspace_logical_paths = sorted(workspace_file_by_logical_path.keys())
    workspace_files = [workspace_file_by_logical_path[path] for path in workspace_logical_paths]
    input_map = ctx.actions.declare_file("projection-freshness/{}/workspace-inputs.tsv".format(ctx.label.name))
    ctx.actions.write(
        output = input_map,
        content = "".join([
            "{}\t{}\n".format(path, workspace_file_by_logical_path[path].path)
            for path in workspace_logical_paths
        ]),
    )

    staged_workspace = ctx.actions.declare_directory(
        "projection-freshness/{}/workspace".format(ctx.label.name),
    )
    regenerated_manifest = ctx.actions.declare_file(
        "projection-freshness/{}/lake-authority.json".format(ctx.label.name),
    )
    regenerated_projection = ctx.actions.declare_file(
        "projection-freshness/{}/BUILD.bazel".format(ctx.label.name),
    )
    metadata = ctx.actions.declare_file(
        "projection-freshness/{}/metadata.json".format(ctx.label.name),
    )
    candidate_lock = ctx.actions.declare_file(
        "projection-freshness/{}/candidate-lock.json".format(ctx.label.name),
    )
    stamp = ctx.actions.declare_file(
        "projection-freshness/{}/verified.stamp".format(ctx.label.name),
    )

    ctx.actions.run(
        executable = export_runner_files_to_run,
        env = {
            "LEAN_PROJECTION_EXPORTER": exporter_files_to_run.executable.path,
            "LEAN_PROJECTION_EXPORTER_RUNFILES": exporter_files_to_run.executable.path + ".runfiles",
            "LEAN_PROJECTION_INPUT_MAP": input_map.path,
            "LEAN_PROJECTION_LEAN_LIB_DIR": toolchain.lean_lib_dir,
            "LEAN_PROJECTION_LEAN_SYSROOT": toolchain.sysroot,
            "LEAN_PROJECTION_MANIFEST": regenerated_manifest.path,
            "LEAN_PROJECTION_PLATFORM": toolchain.platform,
            "LEAN_PROJECTION_STAGED_WORKSPACE": staged_workspace.path,
            "LEAN_PROJECTION_TOOLCHAIN_ID": toolchain.identity,
        },
        inputs = depset(
            direct = workspace_files + [input_map, toolchain.identity_file],
            transitive = [toolchain.files],
        ),
        mnemonic = "LeanProjectionExport",
        outputs = [staged_workspace, regenerated_manifest],
        progress_message = "Exporting fresh Lake authority manifest for {}".format(ctx.label),
        tools = [exporter_files_to_run],
        use_default_shell_env = False,
    )

    ctx.actions.run(
        arguments = [regenerated_manifest.path, regenerated_projection.path],
        env = {
            "HOME": "/nonexistent",
            "LEAN_BAZEL_PLATFORM": toolchain.platform,
            "LEAN_BAZEL_TOOLCHAIN_ID": toolchain.identity,
            "PATH": "",
            "RUNFILES_DIR": renderer_files_to_run.executable.path + ".runfiles",
            "TMPDIR": "/tmp",
        },
        executable = renderer_files_to_run,
        inputs = depset([regenerated_manifest, toolchain.identity_file]),
        mnemonic = "LeanProjectionRender",
        outputs = [regenerated_projection],
        progress_message = "Rendering fresh Bazel projection for {}".format(ctx.label),
        use_default_shell_env = False,
    )

    exporter_sources = _revision_sources(
        ctx.files._exporter_revision_sources,
        "projection exporter revision sources",
    )
    renderer_sources = _revision_sources(
        ctx.files._renderer_revision_sources,
        "projection renderer revision sources",
    )
    verify_env = {
        "LEAN_PROJECTION_COMMITTED_LOCK": ctx.file.committed_lock.path,
        "LEAN_PROJECTION_COMMITTED_MANIFEST": ctx.file.committed_manifest.path,
        "LEAN_PROJECTION_COMMITTED_PROJECTION": ctx.file.committed_projection.path,
        "LEAN_PROJECTION_EXPORTER_BINARY": exporter.raw_executable.path,
        "LEAN_PROJECTION_EXPORTER_SOURCE_COUNT": str(len(exporter_sources)),
        "LEAN_PROJECTION_FRESH_MANIFEST": regenerated_manifest.path,
        "LEAN_PROJECTION_FRESH_PROJECTION": regenerated_projection.path,
        "LEAN_PROJECTION_METADATA": metadata.path,
        "LEAN_PROJECTION_PLATFORM": toolchain.platform,
        "LEAN_PROJECTION_RENDERER_BINARY": renderer.raw_executable.path,
        "LEAN_PROJECTION_RENDERER_SOURCE_COUNT": str(len(renderer_sources)),
        "LEAN_PROJECTION_STAMP": stamp.path,
        "LEAN_PROJECTION_TOOLCHAIN_IDENTITY": toolchain.identity,
    }
    candidate_env = {
        "LEAN_PROJECTION_CANDIDATE_LOCK": candidate_lock.path,
        "LEAN_PROJECTION_EXPORTER_BINARY": exporter.raw_executable.path,
        "LEAN_PROJECTION_EXPORTER_SOURCE_COUNT": str(len(exporter_sources)),
        "LEAN_PROJECTION_FRESH_MANIFEST": regenerated_manifest.path,
        "LEAN_PROJECTION_FRESH_PROJECTION": regenerated_projection.path,
        "LEAN_PROJECTION_PLATFORM": toolchain.platform,
        "LEAN_PROJECTION_RENDERER_BINARY": renderer.raw_executable.path,
        "LEAN_PROJECTION_RENDERER_SOURCE_COUNT": str(len(renderer_sources)),
        "LEAN_PROJECTION_TOOLCHAIN_IDENTITY": toolchain.identity,
    }
    for index in range(len(exporter_sources)):
        logical_name, file = exporter_sources[index]
        verify_env["LEAN_PROJECTION_EXPORTER_SOURCE_{}_NAME".format(index)] = logical_name
        verify_env["LEAN_PROJECTION_EXPORTER_SOURCE_{}_PATH".format(index)] = file.path
        candidate_env["LEAN_PROJECTION_EXPORTER_SOURCE_{}_NAME".format(index)] = logical_name
        candidate_env["LEAN_PROJECTION_EXPORTER_SOURCE_{}_PATH".format(index)] = file.path
    for index in range(len(renderer_sources)):
        logical_name, file = renderer_sources[index]
        verify_env["LEAN_PROJECTION_RENDERER_SOURCE_{}_NAME".format(index)] = logical_name
        verify_env["LEAN_PROJECTION_RENDERER_SOURCE_{}_PATH".format(index)] = file.path
        candidate_env["LEAN_PROJECTION_RENDERER_SOURCE_{}_NAME".format(index)] = logical_name
        candidate_env["LEAN_PROJECTION_RENDERER_SOURCE_{}_PATH".format(index)] = file.path

    candidate_inputs = [
        regenerated_manifest,
        regenerated_projection,
        toolchain.identity_file,
        exporter.raw_executable,
        renderer.raw_executable,
    ] + [entry[1] for entry in exporter_sources] + [entry[1] for entry in renderer_sources]
    ctx.actions.run(
        executable = verifier_files_to_run,
        env = candidate_env,
        inputs = depset(candidate_inputs),
        mnemonic = "LeanProjectionCandidateLock",
        outputs = [candidate_lock],
        progress_message = "Generating projection lock candidate for {}".format(ctx.label),
        use_default_shell_env = False,
    )

    verify_inputs = [
        regenerated_manifest,
        regenerated_projection,
        ctx.file.committed_manifest,
        ctx.file.committed_projection,
        ctx.file.committed_lock,
        toolchain.identity_file,
        exporter.raw_executable,
        renderer.raw_executable,
    ] + [entry[1] for entry in exporter_sources] + [entry[1] for entry in renderer_sources]
    ctx.actions.run(
        executable = verifier_files_to_run,
        env = verify_env,
        inputs = depset(verify_inputs),
        mnemonic = "LeanProjectionVerify",
        outputs = [metadata, stamp],
        progress_message = "Verifying mandatory projection freshness for {}".format(ctx.label),
        use_default_shell_env = False,
    )

    return [
        DefaultInfo(files = depset([stamp])),
        OutputGroupInfo(
            evidence = depset([
                metadata,
                regenerated_manifest,
                regenerated_projection,
            ]),
            regeneration = depset([
                regenerated_manifest,
                regenerated_projection,
                candidate_lock,
            ]),
        ),
        LeanProjectionFreshnessInfo(
            metadata = metadata,
            regenerated_manifest = regenerated_manifest,
            regenerated_projection = regenerated_projection,
            stamp = stamp,
        ),
    ]

lean_projection_freshness = rule(
    implementation = _lean_projection_freshness_impl,
    attrs = {
        "_export_runner": attr.label(
            default = Label("//tools:projection_export_runner"),
            cfg = "exec",
            executable = True,
        ),
        "_exporter": attr.label(
            default = Label("//tools:export_lake_bootstrap"),
            cfg = "exec",
            executable = True,
            providers = [[LeanBinaryInfo]],
        ),
        "_exporter_revision_sources": attr.label_list(
            default = [
                Label("//tools:ExportLake.lean"),
                Label("//tools:LakeModel.lean"),
            ],
            allow_files = True,
        ),
        "_renderer": attr.label(
            default = Label("//tools:render_bazel_bootstrap"),
            cfg = "exec",
            executable = True,
            providers = [[LeanBinaryInfo]],
        ),
        "_renderer_revision_sources": attr.label_list(
            default = [
                Label("//tools:RenderBazel.lean"),
                Label("//tools:LakeModel.lean"),
            ],
            allow_files = True,
        ),
        "_verifier": attr.label(
            default = Label("//tools:projection_verify_runner"),
            cfg = "exec",
            executable = True,
        ),
        "committed_lock": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "committed_manifest": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "committed_projection": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "workspace_inputs": attr.label_list(
            allow_files = True,
        ),
    },
    toolchains = ["//toolchains:lean_toolchain_type"],
)
