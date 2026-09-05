"""Hermetic Lake-authority build checks producing success stamps."""

load("//tools:lean_binary.bzl", "LeanBinaryInfo")
load("//tools:lean_module.bzl", "LeanModuleInfo", "reject_restricted_solver_override")

_LEAN_EXE = "lean_exe"
_LEAN_PROBE = "lean_probe"
_LEAN_SEMANTIC_SUFFIXES = [
    ".olean.server",
    ".olean.private",
    ".olean",
    ".ilean",
    ".ir",
]
_RESERVED_ENVIRONMENT = {
    "HOME": True,
    "LEAN_BAZEL_LAUNCH_CWD": True,
    "LEAN_BAZEL_PLATFORM": True,
    "LEAN_BAZEL_TOOLCHAIN_ID": True,
    "LEAN_PATH": True,
    "PATH": True,
    "RUNFILES_DIR": True,
    "RUNFILES_MANIFEST_FILE": True,
    "TEST_SRCDIR": True,
    "TEST_TMPDIR": True,
    "TEST_WORKSPACE": True,
    "TMPDIR": True,
}

LeanCheckWitnessInfo = provider(
    doc = "Configured lean_check inputs exposed for exact-closure evidence.",
    fields = {
        "cwd": "the normalized execution cwd",
        "freshness_files": "all check- and root-level freshness Files",
        "kind": "the configured check kind",
        "platform": "the configured Lean platform",
        "root_label": "the configured root target label",
        "semantic_inputs": "the exact probe semantic-input depset",
        "setup": "the generated probe setup File, or None",
        "source": "the probe source File, or None",
        "toolchain_identity": "the configured Lean toolchain identity",
    },
)

def _validate_cwd(cwd):
    if not cwd or cwd.startswith("/") or "\\" in cwd:
        fail("lean_check cwd must be a normalized repository-relative directory")
    if cwd == ".":
        return
    for component in cwd.split("/"):
        if not component or component == "." or component == "..":
            fail("lean_check cwd must be a normalized repository-relative directory")

def _validate_environment(environment, kind):
    for key in sorted(environment.keys()):
        if not key or "=" in key:
            fail("lean_check environment keys must be nonempty and must not contain '='")
        if key.startswith("LEAN_CHECK_") or key in _RESERVED_ENVIRONMENT:
            fail("lean_check environment key '{}' is reserved".format(key))
        if kind == _LEAN_PROBE and key == "LEAN_SYSROOT":
            fail("lean_check environment key 'LEAN_SYSROOT' is reserved for lean_probe")

def _action_cwd(package, cwd):
    if cwd == ".":
        return package if package else "."
    return package + "/" + cwd if package else cwd

def _default_files(targets):
    files = []
    for target in targets:
        if DefaultInfo in target:
            files.extend(target[DefaultInfo].files.to_list())
    return files

def _reject_probe_nonimport_semantic_files(description, files):
    for file in files:
        if file.is_directory:
            fail("{} must not contain a TreeArtifact: {}".format(description, file.path))
        for suffix in _LEAN_SEMANTIC_SUFFIXES:
            if file.path.endswith(suffix):
                fail("{} must not contain Lean semantic artifact '{}': {}".format(description, suffix, file.path))

def _relative_to_action_cwd(action_cwd, path):
    base = [] if action_cwd == "." else action_cwd.split("/")
    target = path.split("/")
    common = 0
    for index in range(min(len(base), len(target))):
        if base[index] != target[index]:
            break
        common += 1
    relative = [".."] * (len(base) - common) + target[common:]
    return "/".join(relative) if relative else "."

def _probe_setup_contract(probe, action_cwd):
    import_arts = {}
    import_artifact_files = []
    previous_module = None
    for artifact in probe.import_artifacts:
        if previous_module != None and artifact.module <= previous_module:
            fail("lean_check probe import artifacts must have unique modules in sorted order")
        for file in artifact.files:
            if file.is_directory:
                fail("lean_check probe import artifact records must contain only files: {}".format(file.path))
            import_artifact_files.append(file)
        import_arts[artifact.module] = [
            _relative_to_action_cwd(action_cwd, file.path)
            for file in artifact.files
        ]
        previous_module = artifact.module
    content = {
        "dynlibs": [],
        "importArts": import_arts,
        "isModule": probe.is_module,
        "name": probe.module,
        "options": probe.lean_options,
        "plugins": [],
    }
    if probe.package_id:
        content["package"] = probe.package_id
    return struct(
        content = content,
        import_artifact_files = depset(direct = import_artifact_files),
    )

def _lean_check_impl(ctx):
    if ctx.attr.kind not in [_LEAN_EXE, _LEAN_PROBE]:
        fail("lean_check kind must be 'lean_exe' or 'lean_probe', got '{}'".format(ctx.attr.kind))
    if ctx.attr.expected_exit < 0 or ctx.attr.expected_exit > 255:
        fail("lean_check expected_exit must be between 0 and 255")
    if not ctx.attr.expect_stdout and ctx.attr.expected_stdout:
        fail("lean_check expected_stdout must be empty when expect_stdout is false")
    if not ctx.attr.expect_stderr and ctx.attr.expected_stderr:
        fail("lean_check expected_stderr must be empty when expect_stderr is false")
    _validate_cwd(ctx.attr.cwd)
    _validate_environment(ctx.attr.env, ctx.attr.kind)

    toolchain = ctx.toolchains["//toolchains:lean_toolchain_type"]
    if toolchain.platform not in ["aarch64-darwin", "x86_64-linux"]:
        fail("lean_check received unsupported platform '{}'".format(toolchain.platform))
    action_cwd = _action_cwd(ctx.label.package, ctx.attr.cwd)

    direct_inputs = []
    transitive_inputs = []
    action_tools = []
    check_args = ctx.attr.args
    runner_args = []
    tool = None
    tool_runfiles = ""
    source = ""
    setup = ""
    witness_freshness = []
    witness_semantic_inputs = depset()
    witness_setup = None
    witness_source = None
    direct_inputs.extend(ctx.files.inputs)
    direct_inputs.extend(ctx.files.resources)
    if ctx.file.freshness:
        direct_inputs.append(ctx.file.freshness)
        witness_freshness.append(ctx.file.freshness)

    if ctx.attr.kind == _LEAN_PROBE:
        _reject_probe_nonimport_semantic_files("lean_probe inputs", ctx.files.inputs)
        _reject_probe_nonimport_semantic_files("lean_probe resources", ctx.files.resources)
        if ctx.file.freshness:
            _reject_probe_nonimport_semantic_files("lean_probe freshness", [ctx.file.freshness])

    if ctx.attr.kind == _LEAN_EXE:
        if LeanBinaryInfo not in ctx.attr.root:
            fail("lean_check lean_exe root must provide LeanBinaryInfo")
        binary = ctx.attr.root[LeanBinaryInfo]
        if binary.toolchain_identity != toolchain.identity:
            fail("lean_check executable root toolchain identity does not match the active Lean toolchain")
        files_to_run = ctx.attr.root[DefaultInfo].files_to_run
        if not files_to_run or not files_to_run.executable:
            fail("lean_check lean_exe root has no executable FilesToRunProvider")
        tool = files_to_run.executable
        tool_runfiles = tool.path + ".runfiles"
        action_tools.append(files_to_run)
        direct_inputs.extend(_default_files(ctx.attr.deps))
    else:
        if LeanModuleInfo not in ctx.attr.root:
            fail("lean_check lean_probe root must provide LeanModuleInfo")
        probe = ctx.attr.root[LeanModuleInfo]
        if probe.toolchain_identity != toolchain.identity:
            fail("lean_check probe root toolchain identity does not match the active Lean toolchain")
        consumer_probe_args = probe.weak_lean_args + probe.lean_args + ctx.attr.args
        reject_restricted_solver_override("lean_check lean_probe args", consumer_probe_args)
        probe_setup_contract = _probe_setup_contract(probe, action_cwd)
        probe_setup = ctx.actions.declare_file("check-setups/{}.json".format(ctx.label.name))
        ctx.actions.write(
            output = probe_setup,
            content = json.encode(probe_setup_contract.content),
        )
        tool = toolchain.restricted_compile_runner
        runner_args = toolchain.restricted_compile_runner_args
        check_args = consumer_probe_args + [
            "-Dsat.solver={}".format(_relative_to_action_cwd(
                action_cwd,
                toolchain.restricted_compile_solver.path,
            )),
        ]
        source = probe.source.path
        setup = probe_setup.path
        witness_source = probe.source
        witness_setup = probe_setup
        witness_semantic_inputs = probe_setup_contract.import_artifact_files
        direct_inputs.extend([probe.source, probe_setup, toolchain.identity_file])
        probe_extra_inputs = probe.extra_inputs.to_list()
        _reject_probe_nonimport_semantic_files("lean_probe root extra_inputs", probe_extra_inputs)
        direct_inputs.extend(probe_extra_inputs)
        if probe.freshness:
            _reject_probe_nonimport_semantic_files("lean_probe root freshness", [probe.freshness])
            direct_inputs.append(probe.freshness)
            witness_freshness.append(probe.freshness)
        dep_files = _default_files(ctx.attr.deps)
        _reject_probe_nonimport_semantic_files("lean_probe deps", dep_files)
        direct_inputs.extend(dep_files)
        transitive_inputs.extend([
            probe_setup_contract.import_artifact_files,
            toolchain.restricted_compile_files,
        ])
        action_tools.append(toolchain.restricted_compile_runner)

    stamp = ctx.actions.declare_file("check-stamps/{}.stamp".format(ctx.label.name))
    environment = {
        "HOME": "/nonexistent",
        "LEAN_CHECK_ARG_COUNT": str(len(check_args)),
        "LEAN_CHECK_CWD": action_cwd,
        "LEAN_CHECK_DEP_COUNT": str(len(ctx.attr.deps)),
        "LEAN_CHECK_ENV_COUNT": str(len(ctx.attr.env)),
        "LEAN_CHECK_EXPECT_STDERR": ctx.attr.expected_stderr,
        "LEAN_CHECK_EXPECT_STDERR_PRESENT": "1" if ctx.attr.expect_stderr else "0",
        "LEAN_CHECK_EXPECT_STDOUT": ctx.attr.expected_stdout,
        "LEAN_CHECK_EXPECT_STDOUT_PRESENT": "1" if ctx.attr.expect_stdout else "0",
        "LEAN_CHECK_EXPECTED_EXIT": str(ctx.attr.expected_exit),
        "LEAN_CHECK_KIND": ctx.attr.kind,
        "LEAN_CHECK_PLATFORM": toolchain.platform,
        "LEAN_CHECK_RUNNER_ARG_COUNT": str(len(runner_args)),
        "LEAN_CHECK_SETUP": setup,
        "LEAN_CHECK_SOURCE": source,
        "LEAN_CHECK_STAMP": stamp.path,
        "LEAN_CHECK_TMPDIR": "/tmp",
        "LEAN_CHECK_TOOL": tool.path,
        "LEAN_CHECK_TOOL_RUNFILES": tool_runfiles,
        "LEAN_CHECK_TOOLCHAIN_IDENTITY": toolchain.identity,
        "PATH": "",
        "TMPDIR": "/tmp",
    }
    for index in range(len(check_args)):
        environment["LEAN_CHECK_ARG_{}".format(index)] = check_args[index]
    for index in range(len(runner_args)):
        environment["LEAN_CHECK_RUNNER_ARG_{}".format(index)] = runner_args[index]
    for index in range(len(ctx.attr.env)):
        key = sorted(ctx.attr.env.keys())[index]
        environment["LEAN_CHECK_ENV_KEY_{}".format(index)] = key
        environment["LEAN_CHECK_ENV_VALUE_{}".format(index)] = ctx.attr.env[key]
    for index in range(len(ctx.attr.deps)):
        environment["LEAN_CHECK_DEP_{}".format(index)] = str(ctx.attr.deps[index].label)

    ctx.actions.run(
        env = environment,
        executable = ctx.executable._runner,
        inputs = depset(
            direct = direct_inputs,
            transitive = transitive_inputs,
        ),
        mnemonic = "LeanCheck",
        outputs = [stamp],
        progress_message = "Running Lean authority check {}".format(ctx.label.name),
        tools = action_tools,
        use_default_shell_env = False,
    )
    return [
        DefaultInfo(files = depset([stamp])),
        LeanCheckWitnessInfo(
            cwd = _action_cwd(ctx.label.package, ctx.attr.cwd),
            freshness_files = depset(witness_freshness),
            kind = ctx.attr.kind,
            platform = toolchain.platform,
            root_label = str(ctx.attr.root.label),
            semantic_inputs = witness_semantic_inputs,
            setup = witness_setup,
            source = witness_source,
            toolchain_identity = toolchain.identity,
        ),
    ]

lean_check = rule(
    implementation = _lean_check_impl,
    attrs = {
        "_runner": attr.label(
            default = Label("//tools:lean_check_runner"),
            cfg = "exec",
            executable = True,
        ),
        "args": attr.string_list(),
        "cwd": attr.string(mandatory = True),
        "deps": attr.label_list(allow_files = True),
        "env": attr.string_dict(),
        "expect_stderr": attr.bool(default = False),
        "expect_stdout": attr.bool(default = False),
        "expected_exit": attr.int(mandatory = True),
        "expected_stderr": attr.string(),
        "expected_stdout": attr.string(),
        "freshness": attr.label(allow_single_file = True),
        "inputs": attr.label_list(allow_files = True),
        "kind": attr.string(mandatory = True),
        "resources": attr.label_list(allow_files = True),
        "root": attr.label(mandatory = True),
    },
    toolchains = ["//toolchains:lean_toolchain_type"],
)
