"""Declared Lean SDK toolchain exposed to Bazel actions."""

load(
    "@lean_sdk//:sdk_index.bzl",
    "SDK_ARCHIVE_SHA256",
    "SDK_DIRECT_EDGE_COUNT",
    "SDK_EXTRACTOR_RUNTIME_IDENTITY",
    "SDK_IDENTITY",
    "SDK_IMPORT_ARTIFACT_LAYOUT",
    "SDK_INDEX_SCHEMA",
    "SDK_LEAN_GITHASH",
    "SDK_LEGACY_MAIN_ONLY_MODULES",
    "SDK_MODULES",
    "SDK_MODULE_COUNT",
    "SDK_PLATFORM",
    "SDK_TOPOLOGICAL_ORDER",
)

_SDK_INDEX_SCHEMA = "lean-sdk-graph-v1"
_SDK_IMPORT_ARTIFACT_LAYOUT = ["olean", "ir", "oleanServer", "oleanPrivate"]
_SDK_LEGACY_MAIN_ONLY_MODULES = ["LeanChecker", "Leanc"]

def _expand_sysroot(values, sysroot):
    return [value.replace("$sysroot", sysroot) for value in values]

def _expand_roots(values, sysroot, restricted_sysroot):
    return [
        value.replace("$restricted_sysroot", restricted_sysroot).replace("$sysroot", sysroot)
        for value in values
    ]

def _logical_sdk_files(files, sysroot, description):
    file_by_logical_path = {}
    sysroot_prefix = sysroot + "/"
    for file in files:
        if not file.path.startswith(sysroot_prefix):
            fail("Lean SDK {} file is outside the computed SDK root: {}".format(description, file.path))
        logical_path = file.path[len(sysroot_prefix):]
        if not logical_path or logical_path.startswith("/") or logical_path == ".." or logical_path.startswith("../") or "/../" in logical_path or logical_path.endswith("/.."):
            fail("invalid Lean SDK {}-relative path '{}'".format(description, logical_path))
        if logical_path in file_by_logical_path:
            fail("duplicate Lean SDK {}-relative path '{}'".format(description, logical_path))
        file_by_logical_path[logical_path] = file
    return [
        struct(
            file = file_by_logical_path[logical_path],
            logical_path = logical_path,
        )
        for logical_path in sorted(file_by_logical_path.keys())
    ]

def _sdk_olean_inventory(files, lean_lib_dir):
    lean_lib_prefix = lean_lib_dir + "/"
    sdk_oleans = {}
    for file in files:
        if not file.path.endswith(".olean"):
            continue
        if not file.path.startswith(lean_lib_prefix):
            fail("Lean SDK .olean file is outside the computed Lean library root: {}".format(file.path))
        module_path = file.path[len(lean_lib_prefix):-len(".olean")]
        if not module_path or module_path.startswith("/") or module_path.endswith("/") or "//" in module_path:
            fail("invalid Lean SDK module path '{}'".format(module_path))
        for component in module_path.split("/"):
            if component in ["", ".", ".."]:
                fail("invalid Lean SDK module path '{}'".format(module_path))
        module = module_path.replace("/", ".")
        if module in sdk_oleans:
            fail("duplicate Lean SDK module '{}'".format(module))
        sdk_oleans[module] = file
    if not sdk_oleans:
        fail("Lean SDK distribution contains no .olean files beneath {}".format(lean_lib_dir))
    return sdk_oleans

def _logical_file_map(logical_files, description):
    result = {}
    for entry in logical_files:
        if entry.logical_path in result:
            fail("duplicate Lean SDK {} path '{}'".format(description, entry.logical_path))
        result[entry.logical_path] = entry.file
    return result

def _sdk_ilean_inventory(logical_files, lean_lib_dir, sysroot):
    lean_lib_relative = lean_lib_dir[len(sysroot + "/"):]
    prefix = lean_lib_relative + "/"
    result = {}
    for entry in logical_files:
        path = entry.logical_path
        if not path.startswith(prefix) or not path.endswith(".ilean"):
            fail("Lean SDK IDE artifact is not a .ilean beneath '{}': {}".format(lean_lib_relative, path))
        module_path = path[len(prefix):-len(".ilean")]
        module = module_path.replace("/", ".")
        if not module or module in result:
            fail("invalid or duplicate Lean SDK IDE module '{}'".format(module))
        result[module] = entry.file
    return result

def _resolve_sdk_artifact(file_by_path, path, module, kind, used_paths):
    if type(path) != "string" or not path:
        fail("Lean SDK module '{}' has no {} path".format(module, kind))
    file = file_by_path.get(path)
    if file == None:
        fail("Lean SDK module '{}' {} path is absent from the semantic inventory: {}".format(module, kind, path))
    if path in used_paths:
        fail("Lean SDK semantic artifact path is owned by multiple modules: {}".format(path))
    used_paths[path] = module
    return file

def _sdk_analysis_catalog(ctx, sdk_semantic_files):
    if SDK_INDEX_SCHEMA != _SDK_INDEX_SCHEMA:
        fail("Lean SDK index schema mismatch: expected '{}', got '{}'".format(_SDK_INDEX_SCHEMA, SDK_INDEX_SCHEMA))
    if SDK_IDENTITY != ctx.attr.sdk_identity:
        fail("Lean SDK index identity does not match the configured canonical SDK identity")
    if SDK_PLATFORM != ctx.attr.platform:
        fail("Lean SDK index platform does not match the configured toolchain platform")
    if SDK_EXTRACTOR_RUNTIME_IDENTITY != ctx.attr.restricted_runtime_identity:
        fail("Lean SDK index extractor runtime does not match the configured restricted runtime")
    if "sha256:{}".format(SDK_ARCHIVE_SHA256) not in SDK_IDENTITY:
        fail("Lean SDK index archive digest is not bound into its identity")
    if "githash:{}".format(SDK_LEAN_GITHASH) not in SDK_IDENTITY:
        fail("Lean SDK index Lean revision is not bound into its identity")
    if SDK_IMPORT_ARTIFACT_LAYOUT != _SDK_IMPORT_ARTIFACT_LAYOUT:
        fail("Lean SDK import artifact layout mismatch: expected {}, got {}".format(
            _SDK_IMPORT_ARTIFACT_LAYOUT,
            SDK_IMPORT_ARTIFACT_LAYOUT,
        ))
    if SDK_LEGACY_MAIN_ONLY_MODULES != _SDK_LEGACY_MAIN_ONLY_MODULES:
        fail("Lean SDK legacy main-only module classification mismatch")
    if SDK_MODULE_COUNT != len(SDK_MODULES):
        fail("Lean SDK index module count does not match its module table")
    if SDK_MODULE_COUNT != len(SDK_TOPOLOGICAL_ORDER):
        fail("Lean SDK index module count does not match its topological order")

    file_by_path = _logical_file_map(sdk_semantic_files, "semantic artifact")
    used_paths = {}
    seen_modules = {}
    module_records = {}
    module_closures = {}
    direct_edge_count = 0

    for module in SDK_TOPOLOGICAL_ORDER:
        if module in seen_modules:
            fail("Lean SDK topological order contains duplicate module '{}'".format(module))
        record = SDK_MODULES.get(module)
        if record == None:
            fail("Lean SDK topological order names missing module '{}'".format(module))
        if type(record) != "dict":
            fail("Lean SDK module '{}' record is not a dictionary".format(module))

        is_module = record.get("is_module")
        if type(is_module) != "bool":
            fail("Lean SDK module '{}' has invalid is_module metadata".format(module))
        olean = _resolve_sdk_artifact(file_by_path, record.get("olean"), module, "olean", used_paths)
        artifact_files = [olean]
        ir = None
        olean_server = None
        olean_private = None
        if is_module:
            ir = _resolve_sdk_artifact(file_by_path, record.get("ir"), module, "ir", used_paths)
            olean_server = _resolve_sdk_artifact(file_by_path, record.get("olean_server"), module, "olean.server", used_paths)
            olean_private = _resolve_sdk_artifact(file_by_path, record.get("olean_private"), module, "olean.private", used_paths)
            artifact_files = [olean, ir, olean_server, olean_private]
        else:
            if module not in _SDK_LEGACY_MAIN_ONLY_MODULES:
                fail("Lean SDK module '{}' is unexpectedly classified as legacy main-only".format(module))
            if record.get("ir") != None or record.get("olean_server") != None or record.get("olean_private") != None:
                fail("legacy Lean SDK module '{}' unexpectedly names companion artifacts".format(module))

        imports = record.get("imports")
        if type(imports) != "list":
            fail("Lean SDK module '{}' imports are not a list".format(module))
        dependency_modules = {}
        dependency_name_closures = []
        dependency_file_closures = []
        for edge in imports:
            if (
                type(edge) != "tuple" or
                len(edge) != 4 or
                type(edge[0]) != "string" or
                type(edge[1]) != "bool" or
                type(edge[2]) != "bool" or
                type(edge[3]) != "bool"
            ):
                fail("Lean SDK module '{}' has a malformed import edge".format(module))
            dependency = edge[0]
            direct_edge_count += 1
            if dependency not in SDK_MODULES:
                fail("Lean SDK module '{}' imports missing module '{}'".format(module, dependency))
            if dependency not in seen_modules:
                fail("Lean SDK graph is cyclic or not dependency-first at '{} -> {}'".format(module, dependency))
            if dependency not in dependency_modules:
                dependency_modules[dependency] = True
                dependency_name_closures.append(module_closures[dependency].names)
                dependency_file_closures.append(module_closures[dependency].files)

        module_records[module] = struct(
            artifact_files = artifact_files,
            imports = imports,
            ir = ir,
            is_module = is_module,
            olean = olean,
            olean_private = olean_private,
            olean_server = olean_server,
        )
        module_closures[module] = struct(
            files = depset(
                direct = artifact_files,
                order = "postorder",
                transitive = dependency_file_closures,
            ),
            names = depset(
                direct = [module],
                order = "postorder",
                transitive = dependency_name_closures,
            ),
        )
        seen_modules[module] = True

    if direct_edge_count != SDK_DIRECT_EDGE_COUNT:
        fail("Lean SDK index direct-edge count does not match its module table")
    if len(used_paths) != len(file_by_path):
        unused = sorted([path for path in file_by_path.keys() if path not in used_paths])
        fail("Lean SDK semantic inventory is not exactly represented by the index; unowned paths include {}".format(unused[:5]))
    return module_records, module_closures

def _lean_toolchain_impl(ctx):
    bin_dir = ctx.executable.lean.dirname
    if not bin_dir.endswith("/bin"):
        fail("Lean executable is not inside the SDK bin directory")
    sysroot = bin_dir[:-len("/bin")]
    lean_lib_dir = ctx.attr.lean_lib_dir.replace("$sysroot", sysroot)
    if not lean_lib_dir.startswith(sysroot + "/"):
        fail("Lean library directory is outside the computed SDK root")
    sdk_oleans = _sdk_olean_inventory(ctx.files.distribution, lean_lib_dir)
    restricted_bin_dir = ctx.executable.restricted_lean.dirname
    if not restricted_bin_dir.endswith("/restricted/bin"):
        fail("restricted Lean executable is not inside the restricted SDK bin directory")
    restricted_sysroot = restricted_bin_dir[:-len("/bin")]
    if restricted_sysroot != sysroot + "/restricted":
        fail("restricted Lean compiler root is not nested beneath the canonical SDK root")
    direct_files = [
        ctx.executable.ar,
        ctx.executable.cc,
        ctx.executable.cc_runner,
        ctx.file.identity_file,
        ctx.executable.lake,
        ctx.executable.lean,
        ctx.executable.leanc,
        ctx.executable.linker,
        ctx.executable.runner,
    ]
    if ctx.executable.binary_runner:
        direct_files.append(ctx.executable.binary_runner)
    runtime_file_depset = depset(ctx.files.runtime_files)
    runtime_files = _logical_sdk_files(ctx.files.runtime_files, sysroot, "runtime")
    restricted_compile_file_depset = depset(ctx.files.restricted_compile_files)
    restricted_compile_solver = None
    restricted_compile_solver_path = restricted_bin_dir + "/cadical"
    for file in ctx.files.restricted_compile_files:
        if file.path == restricted_compile_solver_path:
            restricted_compile_solver = file
            break
    if restricted_compile_solver == None:
        fail("restricted Lean compiler closure omits its fixed Cadical solver")
    restricted_runtime_file_depset = depset(ctx.files.restricted_runtime_files)
    restricted_runtime_files = _logical_sdk_files(
        ctx.files.restricted_runtime_files,
        restricted_sysroot,
        "restricted runtime",
    )
    sdk_semantic_files = _logical_sdk_files(ctx.files.sdk_semantic_artifacts, sysroot, "semantic artifact")
    sdk_ide_files = _logical_sdk_files(ctx.files.sdk_ide_artifacts, sysroot, "IDE artifact")
    sdk_modules, sdk_closures = _sdk_analysis_catalog(ctx, sdk_semantic_files)
    sdk_ileans = _sdk_ilean_inventory(sdk_ide_files, lean_lib_dir, sysroot)
    if len(sdk_oleans) != len(sdk_modules):
        fail("canonical SDK .olean inventory does not match the generated SDK index")
    for module in sdk_modules:
        if sdk_oleans.get(module) != sdk_modules[module].olean:
            fail("canonical SDK .olean mapping disagrees with the generated index for '{}'".format(module))
    files = depset(
        direct = direct_files,
        transitive = [depset(ctx.files.distribution), runtime_file_depset],
    )
    return [platform_common.ToolchainInfo(
        ar = ctx.executable.ar,
        bin_dir = bin_dir,
        binary_runner = ctx.executable.binary_runner,
        canonical_files = files,
        canonical_lean = ctx.executable.lean,
        canonical_lean_lib_dir = lean_lib_dir,
        canonical_runner = ctx.executable.runner,
        canonical_runner_args = _expand_sysroot(ctx.attr.runner_args, sysroot),
        canonical_sysroot = sysroot,
        cc = ctx.executable.cc,
        cc_flags = _expand_sysroot(ctx.attr.cc_flags, sysroot),
        cc_flag_templates = ctx.attr.cc_flags,
        cc_link_shared_flags = _expand_sysroot(ctx.attr.cc_link_shared_flags, sysroot),
        cc_link_shared_flag_templates = ctx.attr.cc_link_shared_flags,
        cc_link_static_flags = _expand_sysroot(ctx.attr.cc_link_static_flags, sysroot),
        cc_link_static_flag_templates = ctx.attr.cc_link_static_flags,
        cc_runner = ctx.executable.cc_runner,
        cc_runner_args = _expand_sysroot(ctx.attr.cc_runner_args, sysroot),
        files = files,
        identity = ctx.attr.identity,
        identity_file = ctx.file.identity_file,
        include_dir = ctx.attr.include_dir.replace("$sysroot", sysroot),
        lake = ctx.executable.lake,
        lean = ctx.executable.lean,
        lean_lib_dir = lean_lib_dir,
        leanc = ctx.executable.leanc,
        linker = ctx.executable.linker,
        platform = ctx.attr.platform,
        restricted_compile_files = restricted_compile_file_depset,
        restricted_compile_lean = ctx.executable.restricted_lean,
        restricted_compile_root = restricted_sysroot,
        restricted_compile_runner = ctx.executable.restricted_runner,
        restricted_compile_runner_args = _expand_roots(
            ctx.attr.restricted_runner_args,
            sysroot,
            restricted_sysroot,
        ),
        restricted_compile_solver = restricted_compile_solver,
        restricted_runtime_files = restricted_runtime_files,
        restricted_runtime_file_depset = restricted_runtime_file_depset,
        restricted_runtime_identity = ctx.attr.restricted_runtime_identity,
        runner = ctx.executable.runner,
        runner_args = _expand_sysroot(ctx.attr.runner_args, sysroot),
        runtime_files = runtime_files,
        sdk_ide_file_depset = depset(ctx.files.sdk_ide_artifacts),
        sdk_ide_files = sdk_ide_files,
        sdk_identity = ctx.attr.sdk_identity,
        sdk_ileans = sdk_ileans,
        sdk_closures = sdk_closures,
        sdk_modules = sdk_modules,
        sdk_oleans = sdk_oleans,
        sdk_semantic_file_depset = depset(ctx.files.sdk_semantic_artifacts),
        sdk_semantic_files = sdk_semantic_files,
        sysroot = sysroot,
        system_lib_dir = ctx.attr.system_lib_dir.replace("$sysroot", sysroot),
    )]

lean_toolchain = rule(
    implementation = _lean_toolchain_impl,
    attrs = {
        "ar": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "binary_runner": attr.label(allow_files = True, cfg = "exec", executable = True),
        "cc": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "cc_flags": attr.string_list(),
        "cc_link_shared_flags": attr.string_list(),
        "cc_link_static_flags": attr.string_list(),
        "cc_runner": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "cc_runner_args": attr.string_list(),
        "distribution": attr.label(allow_files = True, mandatory = True),
        "identity": attr.string(mandatory = True),
        "identity_file": attr.label(allow_single_file = True, mandatory = True),
        "include_dir": attr.string(mandatory = True),
        "lake": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "lean": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "lean_lib_dir": attr.string(mandatory = True),
        "leanc": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "linker": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "platform": attr.string(mandatory = True),
        "restricted_compile_files": attr.label(allow_files = True, mandatory = True),
        "restricted_lean": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "restricted_runner": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "restricted_runner_args": attr.string_list(),
        "restricted_runtime_files": attr.label(allow_files = True, mandatory = True),
        "restricted_runtime_identity": attr.string(mandatory = True),
        "runner": attr.label(allow_files = True, cfg = "exec", executable = True, mandatory = True),
        "runner_args": attr.string_list(),
        "runtime_files": attr.label(allow_files = True, mandatory = True),
        "sdk_ide_artifacts": attr.label(allow_files = True, mandatory = True),
        "sdk_identity": attr.string(mandatory = True),
        "sdk_semantic_artifacts": attr.label(allow_files = True, mandatory = True),
        "system_lib_dir": attr.string(mandatory = True),
    },
)
