"""Module-granular Lean elaboration, code generation, and native objects."""

_LEAN_SEMANTIC_SUFFIXES = [
    ".olean.server",
    ".olean.private",
    ".olean",
    ".ilean",
    ".ir",
]

def reject_restricted_solver_override(description, args):
    """Rejects consumer arguments that replace the restricted SAT solver.

    Args:
      description: Human-readable argument source for failure diagnostics.
      args: Lean command-line arguments to validate.
    """
    for index in range(len(args)):
        arg = args[index]
        if arg == "-Dsat.solver" or arg.startswith("-Dsat.solver="):
            fail("{} must not set -Dsat.solver; the restricted Lean toolchain owns the solver policy".format(description))
        if arg == "-D" and index + 1 < len(args):
            option = args[index + 1]
            if option == "sat.solver" or option.startswith("sat.solver="):
                fail("{} must not set -Dsat.solver; the restricted Lean toolchain owns the solver policy".format(description))

def _reject_nonimport_semantic_files(description, files):
    for file in files:
        if file.is_directory:
            fail("{} must not contain a TreeArtifact: {}".format(description, file.path))
        for suffix in _LEAN_SEMANTIC_SUFFIXES:
            if file.path.endswith(suffix):
                fail("{} must not contain Lean semantic artifact '{}': {}".format(description, suffix, file.path))

LeanModuleInfo = provider(
    doc = "A Lean module's transitive compiled artifacts.",
    fields = {
        "c": "the module's generated C file",
        "direct_local_imports": "sorted unique direct workspace-import records",
        "direct_sdk_imports": "sorted unique direct pinned-SDK-import records",
        "extra_inputs": "depset of direct non-module inputs required by the source",
        "ilean": "the module's direct .ilean file",
        "ir": "the module's direct .ir file, or None for a legacy module",
        "import_artifact_files": "depset of exact transitive local and SDK semantic import artifacts",
        "import_artifacts": "sorted exact logical import records consumed by Lean setup",
        "import_oleans": "depset of transitive imported .olean files excluding this module",
        "import_root": "the declared output root used to resolve imported .olean files",
        "is_module": "whether the module participates in Lean's module system",
        "lean_args": "the module's declared strong Lean arguments",
        "lean_options": "the module's decoded Lean options object",
        "module": "the declared Lean module name",
        "olean": "the module's direct .olean file",
        "olean_private": "the module's direct .olean.private file, or None for a legacy module",
        "olean_server": "the module's direct .olean.server file, or None for a legacy module",
        "package_id": "the Lean package identifier, or None when absent",
        "package_name": "the Lake workspace package name",
        "setup": "the exact generated Lean setup JSON File",
        "source": "the declared Lean source File",
        "freshness": "the optional source freshness witness File",
        "sdk_closure_files": "postorder depset of selected transitive SDK semantic artifact Files",
        "sdk_closure_names": "postorder depset of selected transitive SDK logical module names",
        "sdk_identity": "the canonical pinned SDK identity supplying the SDK closure",
        "toolchain_identity": "the exact Lean SDK/toolchain identity used to elaborate the module",
        "transitive_local_ownership": "sorted complete logical local-module ownership records including this module",
        "transitive_local_modules": "sorted complete local module-system graph records including this module",
        "transitive_ileans": "depset of transitive .ilean files",
        "transitive_oleans": "depset of transitive .olean files",
        "weak_lean_args": "the module's declared weak Lean arguments",
    },
)

def _local_ownership_record(module, olean, package_id, package_name, producer_label, toolchain_identity, import_root, is_module):
    return struct(
        import_root = import_root,
        is_module = is_module,
        module = module,
        olean = olean,
        package_id = package_id,
        package_name = package_name,
        producer_label = producer_label,
        toolchain_identity = toolchain_identity,
    )

def _ownership_difference(left, right):
    if left.olean.path != right.olean.path:
        return "artifact"
    if left.package_name != right.package_name:
        return "package_name"
    if left.package_id != right.package_id:
        return "package_id"
    if left.producer_label != right.producer_label:
        return "producer"
    if left.toolchain_identity != right.toolchain_identity:
        return "toolchain"
    if left.import_root != right.import_root:
        return "import_root"
    if left.is_module != right.is_module:
        return "is_module"
    return None

def _merge_local_ownership(ownership_by_module, record):
    previous = ownership_by_module.get(record.module)
    if previous == None:
        ownership_by_module[record.module] = record
        return
    difference = _ownership_difference(previous, record)
    if difference != None:
        fail("local module '{}' has conflicting transitive ownership for {}".format(record.module, difference))

def _import_spec(module, import_all, is_exported, is_meta):
    return struct(
        import_all = import_all,
        is_exported = is_exported,
        is_meta = is_meta,
        module = module,
    )

def _decode_direct_imports(encoded, is_module, direct_modules):
    decoded = json.decode(encoded)
    if type(decoded) != "list":
        fail("direct_imports_json must encode a JSON array")
    specs = []
    for index in range(len(decoded)):
        value = decoded[index]
        if type(value) != "dict":
            fail("direct_imports_json[{}] must be an object".format(index))
        allowed = {
            "importAll": True,
            "isExported": True,
            "isMeta": True,
            "localPackage": True,
            "module": True,
        }
        for key in value.keys():
            if key not in allowed:
                fail("direct_imports_json[{}] has unknown field '{}'".format(index, key))
        for key in ["module", "importAll", "isExported", "isMeta"]:
            if key not in value:
                fail("direct_imports_json[{}] omits '{}'".format(index, key))
        module = value["module"]
        if type(module) != "string" or not module:
            fail("direct_imports_json[{}].module must be nonempty".format(index))
        for key in ["importAll", "isExported", "isMeta"]:
            if type(value[key]) != "bool":
                fail("direct_imports_json[{}].{} must be boolean".format(index, key))
        specs.append(_import_spec(
            module = module,
            import_all = value["importAll"],
            is_exported = value["isExported"],
            is_meta = value["isMeta"],
        ))
    if not specs and direct_modules:
        if is_module:
            fail("module-system source with imports requires direct_imports_json metadata")
        specs = [
            _import_spec(
                module = module,
                import_all = False,
                is_exported = False,
                is_meta = False,
            )
            for module in sorted(direct_modules.keys())
        ]
    declared_modules = {spec.module: True for spec in specs}
    if sorted(declared_modules.keys()) != sorted(direct_modules.keys()):
        fail("direct_imports_json modules do not exactly match deps and sdk_imports")
    return specs

def _file_paths(files):
    return [file.path for file in files]

def _import_spec_values(specs):
    return [
        (spec.module, spec.import_all, spec.is_exported, spec.is_meta)
        for spec in specs
    ]

def _local_module_record(module, is_module, imports, normal_files, all_files):
    return struct(
        all_files = all_files,
        imports = imports,
        is_module = is_module,
        module = module,
        normal_files = normal_files,
    )

def _module_record_difference(left, right):
    if left.is_module != right.is_module:
        return "is_module"
    if _import_spec_values(left.imports) != _import_spec_values(right.imports):
        return "imports"
    if _file_paths(left.normal_files) != _file_paths(right.normal_files):
        return "normal artifacts"
    if _file_paths(left.all_files) != _file_paths(right.all_files):
        return "all artifacts"
    return None

def _merge_local_module(records_by_module, record):
    previous = records_by_module.get(record.module)
    if previous == None:
        records_by_module[record.module] = record
        return
    difference = _module_record_difference(previous, record)
    if difference != None:
        fail("local module '{}' has conflicting transitive module metadata for {}".format(
            record.module,
            difference,
        ))

def _sdk_import_specs(record):
    return [
        _import_spec(
            module = edge[0],
            import_all = edge[1],
            is_exported = edge[2],
            is_meta = edge[3],
        )
        for edge in record.imports
    ]

def _sdk_module_record(module, record):
    normal_files = [record.olean]
    all_files = [record.olean]
    if record.is_module:
        normal_files = [record.olean, record.ir, record.olean_server]
        all_files = normal_files + [record.olean_private]
    return _local_module_record(
        module = module,
        is_module = record.is_module,
        imports = _sdk_import_specs(record),
        normal_files = normal_files,
        all_files = all_files,
    )

def _fetch_transitive_import_artifacts(direct_imports, catalog, non_module):
    """Starlark translation of Lake.fetchTransImportArts; see ../NOTICE."""
    selected = {}
    queue = []
    for imp in direct_imports:
        record = catalog.get(imp.module)
        if record == None:
            fail("direct import '{}' has no local or SDK module metadata".format(imp.module))
        import_all = non_module or imp.import_all
        files = record.all_files if import_all else record.normal_files
        previous = selected.get(imp.module)
        if previous == None or len(files) > len(previous):
            selected[imp.module] = files
        for transitive_imp in record.imports:
            reachable = import_all or transitive_imp.is_exported
            transitive_import_all = non_module or (import_all and transitive_imp.import_all)
            transitive_needs_meta = imp.is_meta or (reachable and transitive_imp.is_meta)
            if reachable or transitive_needs_meta:
                queue.append(struct(
                    import_all = transitive_import_all,
                    module = transitive_imp.module,
                    needs_meta = transitive_needs_meta,
                ))

    meta_visited = {}
    edge_count = 0
    for record in catalog.values():
        edge_count += len(record.imports)

    # Lake's worklist may elaborate each module once normally, once for a
    # meta widening, and once for an import-all widening. Starlark deliberately
    # has no unbounded while loop, so use that semantic bound and fail closed
    # if a future Lean algorithm exceeds it.
    max_steps = len(queue) + 3 * edge_count + 1
    for _ in range(max_steps):
        if not queue:
            break
        entry = queue.pop()
        record = catalog.get(entry.module)
        if record == None:
            fail("transitive import '{}' has no local or SDK module metadata".format(entry.module))
        needs_meta = entry.needs_meta and entry.module not in meta_visited
        previous = selected.get(entry.module)
        if previous != None and not ((entry.import_all or needs_meta) and len(previous) == 3):
            continue
        selected[entry.module] = record.all_files if entry.import_all else record.normal_files
        if entry.import_all or needs_meta:
            meta_visited[entry.module] = True
        for imp in record.imports:
            reachable = entry.import_all or imp.is_exported
            import_all = non_module or (entry.import_all and imp.import_all)
            transitive_needs_meta = needs_meta or (reachable and imp.is_meta)
            if reachable or transitive_needs_meta:
                queue.append(struct(
                    import_all = import_all,
                    module = imp.module,
                    needs_meta = transitive_needs_meta,
                ))
    if queue:
        fail("Lean module-system import traversal exceeded its proven widening bound")
    return selected

LeanNativeInfo = provider(
    doc = "Lazily demanded native-object closures for a Lean module.",
    fields = {
        "export_object": "the module's object with exported Lean symbols",
        "object": "the module's object without exported Lean symbols",
        "transitive_export_objects": "postorder depset of exported-symbol objects",
        "transitive_objects": "postorder depset of non-export objects",
    },
)

def _lean_module_impl(ctx):
    if ctx.attr.backend != "c":
        fail("lean_module currently supports only the qualified C backend; leanir is not qualified for production use")
    if ctx.attr.precompile_modules:
        fail("lean_module does not yet support precompiled modules")
    if not ctx.attr.package_name:
        fail("lean_module package_name must be nonempty")
    reject_restricted_solver_override("lean_module weak_lean_args", ctx.attr.weak_lean_args)
    reject_restricted_solver_override("lean_module lean_args", ctx.attr.lean_args)

    toolchain = ctx.toolchains["//toolchains:lean_toolchain_type"]
    module_rel = ctx.attr.module.replace(".", "/")
    olean = ctx.actions.declare_file("olean-root/{}.olean".format(module_rel))
    ilean = ctx.actions.declare_file("olean-root/{}.ilean".format(module_rel))
    ir = ctx.actions.declare_file("olean-root/{}.ir".format(module_rel)) if ctx.attr.is_module else None
    olean_server = ctx.actions.declare_file("olean-root/{}.olean.server".format(module_rel)) if ctx.attr.is_module else None
    olean_private = ctx.actions.declare_file("olean-root/{}.olean.private".format(module_rel)) if ctx.attr.is_module else None
    c_file = ctx.actions.declare_file("c-root/{}.c".format(module_rel))
    object_file = ctx.actions.declare_file("native-root/{}.o".format(module_rel))
    export_object = ctx.actions.declare_file("native-root/{}.o.export".format(module_rel))
    setup = ctx.actions.declare_file("setups/{}.json".format(module_rel))
    lean_options = json.decode(ctx.attr.lean_options)
    if type(lean_options) != "dict":
        fail("lean_options must encode a JSON object")
    if lean_options.get("compiler.postponeCompile") == True:
        fail("lean_module does not support compiler.postponeCompile; the qualified C action requires direct code generation")
    _reject_nonimport_semantic_files("lean_module extra_inputs", ctx.files.extra_inputs)
    if ctx.file.freshness:
        _reject_nonimport_semantic_files("lean_module freshness", [ctx.file.freshness])
    import_root = olean.path[:-len(module_rel + ".olean")]

    local_dep_infos = {}
    local_dep_labels = {}
    local_dep_targets = {}
    for dep in ctx.attr.deps:
        info = dep[LeanModuleInfo]
        producer_label = str(dep.label)
        if info.toolchain_identity != toolchain.identity:
            fail("local import '{}' uses a different Lean toolchain".format(info.module))
        if not info.package_name:
            fail("local import '{}' has no package_name".format(info.module))
        if info.import_root != import_root:
            fail("local import '{}' is outside this module's declared import root".format(info.module))
        if info.module == ctx.attr.module:
            fail("module '{}' imports itself".format(ctx.attr.module))
        if info.module in local_dep_infos:
            previous = local_dep_infos[info.module]
            if previous.olean.path != info.olean.path or previous.package_name != info.package_name or previous.package_id != info.package_id or local_dep_labels[info.module] != producer_label:
                fail("local import '{}' has conflicting producers".format(info.module))
            continue
        local_dep_infos[info.module] = info
        local_dep_labels[info.module] = producer_label
        local_dep_targets[info.module] = dep

    sdk_olean_by_module = {}
    for module in ctx.attr.sdk_imports:
        if not module:
            fail("sdk_imports entries must be nonempty")
        if module in local_dep_infos:
            fail("import '{}' is declared as both local and SDK-owned".format(module))
        sdk_olean = toolchain.sdk_oleans.get(module)
        if sdk_olean == None:
            fail("Lean SDK does not provide imported module '{}'".format(module))
        if module in sdk_olean_by_module:
            if sdk_olean_by_module[module].path != sdk_olean.path:
                fail("SDK import '{}' resolves to conflicting artifacts".format(module))
            continue
        sdk_olean_by_module[module] = sdk_olean

    direct_module_owners = {module: True for module in local_dep_infos.keys()}
    for module in sdk_olean_by_module.keys():
        direct_module_owners[module] = True
    direct_import_specs = _decode_direct_imports(
        ctx.attr.direct_imports_json,
        ctx.attr.is_module,
        direct_module_owners,
    )

    local_modules = sorted(local_dep_infos.keys())
    local_ownership_by_module = {}
    for module in local_modules:
        info = local_dep_infos[module]
        if info.sdk_identity != toolchain.sdk_identity:
            fail("local import '{}' uses a different canonical Lean SDK".format(module))
        direct_record = None
        for record in info.transitive_local_ownership:
            if not record.module or not record.package_name:
                fail("local import '{}' propagates malformed ownership metadata".format(module))
            if record.module == ctx.attr.module:
                fail("module '{}' has a transitive local import cycle".format(ctx.attr.module))
            if record.toolchain_identity != toolchain.identity:
                fail("transitive local module '{}' uses a different Lean toolchain".format(record.module))
            if record.module in toolchain.sdk_modules:
                fail("local module '{}' collides with a globally owned Lean SDK module".format(record.module))
            _merge_local_ownership(local_ownership_by_module, record)
            if record.module == module:
                direct_record = record
        expected_direct_record = _local_ownership_record(
            module = info.module,
            olean = info.olean,
            package_id = info.package_id,
            package_name = info.package_name,
            producer_label = local_dep_labels[module],
            toolchain_identity = info.toolchain_identity,
            import_root = info.import_root,
            is_module = info.is_module,
        )
        if direct_record == None:
            fail("local import '{}' omits its own transitive ownership record".format(module))
        difference = _ownership_difference(direct_record, expected_direct_record)
        if difference != None:
            fail("local import '{}' provider has a mismatched {} ownership field".format(module, difference))

    if ctx.attr.module in local_ownership_by_module:
        fail("module '{}' has a transitive local import cycle".format(ctx.attr.module))
    if ctx.attr.module in toolchain.sdk_modules:
        fail("local module '{}' collides with a globally owned Lean SDK module".format(ctx.attr.module))
    current_ownership = _local_ownership_record(
        module = ctx.attr.module,
        olean = olean,
        package_id = ctx.attr.package_id if ctx.attr.package_id else None,
        package_name = ctx.attr.package_name,
        producer_label = str(ctx.label),
        toolchain_identity = toolchain.identity,
        import_root = import_root,
        is_module = ctx.attr.is_module,
    )
    _merge_local_ownership(local_ownership_by_module, current_ownership)
    transitive_local_ownership = [
        local_ownership_by_module[module]
        for module in sorted(local_ownership_by_module.keys())
    ]

    local_module_records_by_name = {}
    for module in local_modules:
        info = local_dep_infos[module]
        if not hasattr(info, "transitive_local_modules"):
            fail("local import '{}' omits transitive module-system metadata".format(module))
        for record in info.transitive_local_modules:
            if record.module in toolchain.sdk_modules:
                fail("local module '{}' collides with a globally owned Lean SDK module".format(record.module))
            _merge_local_module(local_module_records_by_name, record)

    normal_files = [olean]
    all_files = [olean]
    if ctx.attr.is_module:
        normal_files = [olean, ir, olean_server]
        all_files = normal_files + [olean_private]
    current_module_record = _local_module_record(
        module = ctx.attr.module,
        is_module = ctx.attr.is_module,
        imports = direct_import_specs,
        normal_files = normal_files,
        all_files = all_files,
    )
    _merge_local_module(local_module_records_by_name, current_module_record)
    transitive_local_modules = [
        local_module_records_by_name[module]
        for module in sorted(local_module_records_by_name.keys())
    ]

    sdk_modules = sorted(sdk_olean_by_module.keys())
    direct_local_imports = [
        struct(
            module = module,
            olean = local_dep_infos[module].olean,
            package_id = local_dep_infos[module].package_id,
            package_name = local_dep_infos[module].package_name,
            producer_label = local_dep_labels[module],
            toolchain_identity = local_dep_infos[module].toolchain_identity,
        )
        for module in local_modules
    ]
    direct_sdk_imports = [
        struct(
            module = module,
            olean = sdk_olean_by_module[module],
            producer_identity = toolchain.identity,
        )
        for module in sdk_modules
    ]

    dependency_sdk_name_closures = []
    dependency_sdk_file_closures = []
    for module in local_modules:
        info = local_dep_infos[module]
        for sdk_module in info.sdk_closure_names.to_list():
            if sdk_module not in toolchain.sdk_modules:
                fail("local import '{}' propagates unknown SDK module '{}'".format(module, sdk_module))
        dependency_sdk_name_closures.append(info.sdk_closure_names)
        dependency_sdk_file_closures.append(info.sdk_closure_files)
    direct_sdk_name_closures = [toolchain.sdk_closures[module].names for module in sdk_modules]
    direct_sdk_file_closures = [toolchain.sdk_closures[module].files for module in sdk_modules]
    sdk_closure_names = depset(
        order = "postorder",
        transitive = dependency_sdk_name_closures + direct_sdk_name_closures,
    )
    sdk_closure_files = depset(
        order = "postorder",
        transitive = dependency_sdk_file_closures + direct_sdk_file_closures,
    )

    module_catalog = {
        module: record
        for module, record in local_module_records_by_name.items()
        if module != ctx.attr.module
    }
    for module in toolchain.sdk_modules.keys():
        if module in module_catalog:
            fail("module '{}' is owned by both the local graph and the Lean SDK".format(module))
        module_catalog[module] = _sdk_module_record(module, toolchain.sdk_modules[module])
    selected_import_artifacts = _fetch_transitive_import_artifacts(
        direct_import_specs,
        module_catalog,
        not ctx.attr.is_module,
    )
    import_artifacts_by_module = {
        module: struct(files = files, module = module)
        for module, files in selected_import_artifacts.items()
    }
    import_artifacts = [
        import_artifacts_by_module[module]
        for module in sorted(import_artifacts_by_module.keys())
    ]
    import_artifact_files = depset(direct = [
        file
        for record in import_artifacts
        for file in record.files
    ])
    setup_content = {
        "dynlibs": [],
        "importArts": {
            record.module: [file.path for file in record.files]
            for record in import_artifacts
        },
        "isModule": ctx.attr.is_module,
        "name": ctx.attr.module,
        "options": lean_options,
        "plugins": [],
    }
    if ctx.attr.package_id:
        setup_content["package"] = ctx.attr.package_id
    ctx.actions.write(
        output = setup,
        content = json.encode(setup_content),
    )

    dep_oleans = [local_dep_infos[module].transitive_oleans for module in local_modules]
    dep_ileans = [local_dep_infos[module].transitive_ileans for module in local_modules]
    dep_objects = [local_dep_targets[module][LeanNativeInfo].transitive_objects for module in local_modules]
    dep_export_objects = [local_dep_targets[module][LeanNativeInfo].transitive_export_objects for module in local_modules]
    transitive_oleans = depset([olean], transitive = dep_oleans)
    import_oleans = depset(transitive = dep_oleans)
    transitive_ileans = depset([ilean], transitive = dep_ileans)
    transitive_objects = depset(
        [object_file],
        order = "postorder",
        transitive = dep_objects,
    )
    transitive_export_objects = depset(
        [export_object],
        order = "postorder",
        transitive = dep_export_objects,
    )
    restricted_lean_tools = depset(
        direct = [toolchain.restricted_compile_lean, toolchain.restricted_compile_runner],
        transitive = [toolchain.restricted_compile_files],
    )
    cc_tools = depset(
        direct = [toolchain.cc, toolchain.cc_runner, toolchain.identity_file],
        transitive = [toolchain.files],
    )

    action_env = {
        "HOME": "/nonexistent",
        "LEAN_BAZEL_PLATFORM": toolchain.platform,
        "LEAN_BAZEL_TOOLCHAIN_ID": toolchain.identity,
        "LEAN_PATH": import_root,
        "PATH": "",
        "TMPDIR": "/tmp",
    }
    restricted_lean_env = {
        "HOME": "/nonexistent",
        "LEAN_BAZEL_PLATFORM": toolchain.platform,
        "LEAN_BAZEL_TOOLCHAIN_ID": toolchain.identity,
        "PATH": "",
        "TMPDIR": "/tmp",
    }
    lean_direct_inputs = [ctx.file.src, setup, toolchain.identity_file] + ctx.files.extra_inputs
    if ctx.file.freshness:
        lean_direct_inputs.append(ctx.file.freshness)

    # Keep ambient PATH unavailable. bv_decide reaches only the declared Cadical
    # input through -Dsat.solver; restricted_compile_files carries it in the action.
    lean_outputs = [olean, ilean, c_file]
    if ctx.attr.is_module:
        lean_outputs.extend([ir, olean_server, olean_private])
    ctx.actions.run(
        arguments = toolchain.restricted_compile_runner_args + ctx.attr.weak_lean_args + ctx.attr.lean_args + [
            "-Dsat.solver={}".format(toolchain.restricted_compile_solver.path),
            ctx.file.src.path,
            "-o",
            olean.path,
            "-i",
            ilean.path,
            "-c",
            c_file.path,
            "--setup",
            setup.path,
            "--json",
        ],
        env = restricted_lean_env,
        executable = toolchain.restricted_compile_runner,
        inputs = depset(
            direct = lean_direct_inputs,
            transitive = [import_artifact_files, toolchain.restricted_compile_files],
        ),
        mnemonic = "LeanCompile",
        outputs = lean_outputs,
        progress_message = "Compiling Lean module {}".format(ctx.attr.module),
        tools = restricted_lean_tools,
    )

    def compile_native(output, extra_args, description):
        ctx.actions.run(
            arguments = toolchain.cc_runner_args + [
                "-c",
                "-o",
                output.path,
                c_file.path,
                "-I",
                toolchain.include_dir,
            ] + toolchain.cc_flags + ctx.attr.weak_leanc_args + ctx.attr.leanc_args + extra_args,
            env = action_env,
            executable = toolchain.cc_runner,
            inputs = depset(
                direct = [c_file, toolchain.identity_file],
                transitive = [toolchain.files],
            ),
            mnemonic = "LeanNativeCompile",
            outputs = [output],
            progress_message = "Compiling {} native object for {}".format(description, ctx.attr.module),
            tools = cc_tools,
        )

    compile_native(object_file, [], "non-export")
    compile_native(export_object, ["-DLEAN_EXPORTING"], "export")

    return [
        DefaultInfo(files = depset(lean_outputs)),
        LeanModuleInfo(
            c = c_file,
            direct_local_imports = direct_local_imports,
            direct_sdk_imports = direct_sdk_imports,
            extra_inputs = depset(ctx.files.extra_inputs),
            freshness = ctx.file.freshness,
            ilean = ilean,
            ir = ir,
            import_artifact_files = import_artifact_files,
            import_artifacts = import_artifacts,
            import_oleans = import_oleans,
            import_root = import_root,
            is_module = ctx.attr.is_module,
            lean_args = ctx.attr.lean_args,
            lean_options = lean_options,
            module = ctx.attr.module,
            olean = olean,
            olean_private = olean_private,
            olean_server = olean_server,
            package_id = ctx.attr.package_id if ctx.attr.package_id else None,
            package_name = ctx.attr.package_name,
            setup = setup,
            source = ctx.file.src,
            sdk_closure_files = sdk_closure_files,
            sdk_closure_names = sdk_closure_names,
            sdk_identity = toolchain.sdk_identity,
            toolchain_identity = toolchain.identity,
            transitive_local_ownership = transitive_local_ownership,
            transitive_local_modules = transitive_local_modules,
            transitive_ileans = transitive_ileans,
            transitive_oleans = transitive_oleans,
            weak_lean_args = ctx.attr.weak_lean_args,
        ),
        LeanNativeInfo(
            export_object = export_object,
            object = object_file,
            transitive_export_objects = transitive_export_objects,
            transitive_objects = transitive_objects,
        ),
        OutputGroupInfo(
            native_export_objects = transitive_export_objects,
            native_objects = transitive_objects,
        ),
    ]

lean_module = rule(
    implementation = _lean_module_impl,
    attrs = {
        "backend": attr.string(default = "c"),
        "deps": attr.label_list(providers = [[LeanModuleInfo, LeanNativeInfo]]),
        "direct_imports_json": attr.string(default = "[]"),
        "extra_inputs": attr.label_list(allow_files = True),
        "freshness": attr.label(allow_single_file = True),
        "is_module": attr.bool(default = False),
        "lean_args": attr.string_list(),
        "lean_options": attr.string(default = "{}"),
        "leanc_args": attr.string_list(),
        "module": attr.string(mandatory = True),
        "package_id": attr.string(),
        "package_name": attr.string(mandatory = True),
        "precompile_modules": attr.bool(default = False),
        "sdk_imports": attr.string_list(mandatory = True),
        "src": attr.label(allow_single_file = [".lean"], mandatory = True),
        "weak_lean_args": attr.string_list(),
        "weak_leanc_args": attr.string_list(),
    },
    toolchains = ["//toolchains:lean_toolchain_type"],
)
