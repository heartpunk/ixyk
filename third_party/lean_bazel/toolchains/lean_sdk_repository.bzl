"""Pinned upstream Lean SDK repository selected for the execution host."""

_LEAN_GITHASH = "68218e876d2a38b1985b8590fff244a83c321783"

_DARWIN_AARCH64 = struct(
    archive_platform = "darwin_aarch64",
    binary_runner = None,
    cc_runner = "@lean_sdk//:bin/clang",
    cc_runner_args = [],
    compatible_with = [
        "@platforms//os:macos",
        "@platforms//cpu:aarch64",
    ],
    linker = "@lean_sdk//:bin/ld64.lld",
    sdk_linker_path = "bin/ld64.lld",
    platform = "aarch64-darwin",
    runner = "@lean_sdk//:bin/lean",
    runner_args = [],
    restricted_runner = "@lean_sdk//:restricted/bin/lean",
    restricted_runner_args = [],
    runtime_files = "@lean_sdk//:runtime_files",
    sha256 = "264105500c8abdf37b68ffe03390a783ed259807807222698da8dd92d6ce0a27",
    strip_prefix = "lean-4.31.0-darwin_aarch64",
    url = "https://github.com/leanprover/lean4/releases/download/v4.31.0/lean-4.31.0-darwin_aarch64.tar.zst",
)

_LINUX_X86_64 = struct(
    archive_platform = "linux",
    binary_runner = "//toolchains:lean_binary_runner",
    cc_runner = "//toolchains:lean_sdk_launcher",
    cc_runner_args = ["$sysroot", "clang"],
    compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    linker = "//toolchains:ld.lld",
    sdk_linker_path = "bin/ld.lld",
    platform = "x86_64-linux",
    runner = "//toolchains:lean_sdk_launcher",
    runner_args = ["$sysroot", "lean"],
    restricted_runner = "//toolchains:lean_sdk_launcher",
    restricted_runner_args = ["$restricted_sysroot", "lean"],
    runtime_files = "@lean_sdk//:runtime_files",
    sha256 = "07a633cc8d9151cbc08825ea4cdda50d4b02a2c9cb852c0131b13046f49cad7f",
    strip_prefix = "lean-4.31.0-linux",
    url = "https://github.com/leanprover/lean4/releases/download/v4.31.0/lean-4.31.0-linux.tar.zst",
)

def _host_config(repository_ctx):
    os_name = repository_ctx.os.name.lower()
    arch = repository_ctx.os.arch.lower()
    if os_name in ["darwin", "mac os x", "macos"] and arch in ["aarch64", "arm64"]:
        return _DARWIN_AARCH64, repository_ctx.attr._darwin_manifest
    if os_name == "linux" and arch in ["amd64", "x86_64"]:
        return _LINUX_X86_64, repository_ctx.attr._linux_manifest
    fail("unsupported Lean SDK execution host: {} {}".format(os_name, arch))

def _normalize_flag(value, raw_sysroot):
    normalized = value.replace(raw_sysroot, "$sysroot")
    for forbidden in ["/Users/", "/home/", "/nix/store/", ".elan"]:
        if forbidden in normalized:
            fail("Lake toolchain flag retains undeclared host path: {}".format(normalized))
    return normalized

def _sdk_relative_path(value, raw_sysroot, description):
    prefix = raw_sysroot + "/"
    if not value.startswith(prefix):
        fail("{} must be beneath the canonical SDK root: {}".format(description, value))
    relative = value[len(prefix):]
    if not relative or relative.startswith("/") or "\\" in relative:
        fail("{} is not a normalized SDK-relative path: {}".format(description, relative))
    for component in relative.split("/"):
        if component in ["", ".", ".."]:
            fail("{} contains an invalid component: {}".format(description, relative))
    return relative

def _render_config(config, toolchain, runtime_identity):
    raw_sysroot = toolchain["sysroot"]
    if toolchain["githash"] != _LEAN_GITHASH:
        fail("Lake manifest githash does not match the pinned Lean SDK")
    if toolchain["platform"] != config.platform:
        fail("Lake manifest platform does not match the selected Lean SDK")
    identity = "lean-4.31.0:{}:sha256:{}:githash:{}".format(
        config.platform,
        config.sha256,
        _LEAN_GITHASH,
    )
    values = {
        "LEAN_AR": toolchain["ar"],
        "LEAN_BINARY_RUNNER": config.binary_runner,
        "LEAN_CC": toolchain["cc"],
        "LEAN_CC_FLAGS": [_normalize_flag(value, raw_sysroot) for value in toolchain["ccFlags"]],
        "LEAN_CC_LINK_SHARED_FLAGS": [_normalize_flag(value, raw_sysroot) for value in toolchain["ccLinkSharedFlags"]],
        "LEAN_CC_LINK_STATIC_FLAGS": [_normalize_flag(value, raw_sysroot) for value in toolchain["ccLinkStaticFlags"]],
        "LEAN_CC_RUNNER": config.cc_runner,
        "LEAN_CC_RUNNER_ARGS": config.cc_runner_args,
        "LEAN_EXEC_COMPATIBLE_WITH": config.compatible_with,
        "LEAN_GITHASH": _LEAN_GITHASH,
        "LEAN_INCLUDE_DIR": toolchain["includeDir"],
        "LEAN_LEAN": toolchain["lean"],
        "LEAN_LEANC": toolchain["leanc"],
        "LEAN_LEANIR": toolchain["leanir"],
        "LEAN_LEAN_LIB_DIR": toolchain["leanLibDir"],
        "LEAN_LINKER": config.linker,
        "LEAN_PLATFORM": config.platform,
        "LEAN_RESTRICTED_COMPILE_FILES": "@lean_sdk//:restricted_compile_files",
        "LEAN_RESTRICTED_LEAN": "@lean_sdk//:restricted/bin/lean",
        "LEAN_RESTRICTED_RUNNER": config.restricted_runner,
        "LEAN_RESTRICTED_RUNNER_ARGS": config.restricted_runner_args,
        "LEAN_RESTRICTED_RUNTIME_FILES": "@lean_sdk//:restricted_runtime_files",
        "LEAN_RESTRICTED_RUNTIME_IDENTITY": runtime_identity,
        "LEAN_RUNNER": config.runner,
        "LEAN_RUNNER_ARGS": config.runner_args,
        "LEAN_RUNTIME_FILES": config.runtime_files,
        "LEAN_SDK_IDE_ARTIFACTS": "@lean_sdk//:sdk_ide_artifacts",
        "LEAN_SDK_IDENTITY": identity,
        "LEAN_SDK_SEMANTIC_ARTIFACTS": "@lean_sdk//:sdk_semantic_artifacts",
        "LEAN_SYSTEM_LIB_DIR": toolchain["systemLibDir"],
    }
    return "\n".join(["{} = {}".format(key, repr(values[key])) for key in sorted(values.keys())]) + "\n", identity

def _runtime_output(repository_ctx, name):
    root = repository_ctx.getenv(name)
    if not root or not root.startswith("/nix/store/"):
        fail("{} must identify a prepared immutable runtime output; use the pinned Ixyk environment".format(name))
    if not repository_ctx.path(root).exists:
        fail("prepared runtime output is missing: {}".format(root))
    return root

def _copy_linux_runtime(repository_ctx):
    cp = repository_ctx.which("cp")
    mkdir = repository_ctx.which("mkdir")
    if not cp or not mkdir:
        fail("Linux Lean SDK setup requires cp and mkdir to materialize the pinned glibc runtime")
    output = _runtime_output(repository_ctx, "LEAN_BAZEL_RUNTIME_ROOT")
    destination = repository_ctx.path("runtime-glibc")
    create = repository_ctx.execute([mkdir, "-p", destination])
    if create.return_code != 0:
        fail("failed to create Lean glibc runtime directory: {}".format(create.stderr))
    copied = repository_ctx.execute([cp, "-RL", output + "/lib/.", destination])
    if copied.return_code != 0:
        fail("failed to copy pinned Lean glibc runtime: {}".format(copied.stderr))
    output_components = output.split("/")
    return output_components[len(output_components) - 1]

def _copy_regular(repository_ctx, source, destination):
    cp = repository_ctx.which("cp")
    mkdir = repository_ctx.which("mkdir")
    cmp = repository_ctx.which("cmp")
    if not cp or not mkdir or not cmp:
        fail("restricted Lean SDK setup requires cp, mkdir, and cmp")
    source_path = repository_ctx.path(source)
    destination_path = repository_ctx.path(destination)
    if not source_path.exists:
        fail("restricted Lean SDK source does not exist: {}".format(source))
    created = repository_ctx.execute([mkdir, "-p", destination_path.dirname])
    if created.return_code != 0:
        fail("failed to create restricted Lean SDK directory: {}".format(created.stderr))
    copied = repository_ctx.execute([cp, "-RL", source_path, destination_path])
    if copied.return_code != 0:
        fail("failed to copy restricted Lean SDK file {}: {}".format(source, copied.stderr))
    compared = repository_ctx.execute([cmp, source_path, destination_path])
    if compared.return_code != 0:
        fail("restricted Lean SDK copy differs from canonical source: {}".format(source))

def _copy_linux_compile_tools(repository_ctx):
    output = _runtime_output(repository_ctx, "LEAN_BAZEL_COMPILE_TOOLS_ROOT")
    _copy_regular(repository_ctx, output + "/bin/cadical", "restricted/bin/cadical")

def _restricted_command(repository_ctx, config, arguments):
    lean = repository_ctx.path("restricted/bin/lean")
    if config.platform == "x86_64-linux":
        loader = repository_ctx.path("restricted/runtime-glibc/ld-linux-x86-64.so.2")
        library_path = ":".join([
            str(repository_ctx.path("restricted/runtime-glibc")),
            str(repository_ctx.path("restricted/lib")),
            str(repository_ctx.path("restricted/lib/lean")),
        ])
        return [
            loader,
            "--library-path",
            library_path,
            "--argv0",
            lean,
            lean,
        ] + arguments
    return [lean] + arguments

def _run_restricted(repository_ctx, config, arguments):
    return repository_ctx.execute(
        _restricted_command(repository_ctx, config, arguments),
        environment = {
            "DYLD_LIBRARY_PATH": "",
            "HOME": "/nonexistent",
            "LD_LIBRARY_PATH": "",
            "LEAN_PATH": "",
            "LEAN_SYSROOT": "",
            "PATH": "",
        },
        timeout = 60,
    )

def _materialize_restricted_runtime(repository_ctx, config):
    # The SDK Cadical uses a generic /lib64 loader and cannot run on NixOS, so
    # Linux uses the pinned static 2.1.2 build. Darwin uses the SDK binary directly.
    if config.platform == "x86_64-linux":
        _copy_linux_compile_tools(repository_ctx)
    else:
        _copy_regular(repository_ctx, "bin/cadical", "restricted/bin/cadical")
    _copy_regular(repository_ctx, "bin/lean", "restricted/bin/lean")
    copied_libraries = []
    for library in repository_ctx.path("lib/lean").readdir():
        name = library.basename
        is_runtime = name.startswith("libInit_shared") or name.startswith("libleanshared")
        is_shared = name.endswith(".dylib") or ".so" in name
        if is_runtime and is_shared:
            _copy_regular(repository_ctx, "lib/lean/" + name, "restricted/lib/lean/" + name)
            copied_libraries.append(name)
    if not copied_libraries:
        fail("restricted Lean SDK runtime found no compiler shared libraries")
    if config.platform == "x86_64-linux":
        cp = repository_ctx.which("cp")
        mkdir = repository_ctx.which("mkdir")
        destination = repository_ctx.path("restricted/runtime-glibc")
        created = repository_ctx.execute([mkdir, "-p", destination])
        if created.return_code != 0:
            fail("failed to create restricted glibc runtime directory: {}".format(created.stderr))
        copied = repository_ctx.execute([cp, "-RL", str(repository_ctx.path("runtime-glibc")) + "/.", destination])
        if copied.return_code != 0:
            fail("failed to copy restricted glibc runtime: {}".format(copied.stderr))

    prefix = _run_restricted(repository_ctx, config, ["--print-prefix"])
    expected_prefix = str(repository_ctx.path("restricted"))
    if prefix.return_code != 0 or prefix.stdout.strip() != expected_prefix:
        fail("restricted Lean prefix mismatch: expected {}, got stdout={!r}, stderr={!r}".format(
            expected_prefix,
            prefix.stdout,
            prefix.stderr,
        ))
    version = _run_restricted(repository_ctx, config, ["--version"])
    if version.return_code != 0:
        fail("restricted Lean failed minimal startup: {}".format(version.stderr))
    repository_ctx.file(
        "restricted-unknown-module.lean",
        "import Definitely.Missing.Restricted.Sdk.Module\n",
    )
    missing = _run_restricted(repository_ctx, config, [repository_ctx.path("restricted-unknown-module.lean")])
    if missing.return_code == 0:
        fail("restricted Lean unexpectedly resolved an undeclared module")
    diagnostic = missing.stdout + "\n" + missing.stderr
    if "unknown module" not in diagnostic and "unknown package" not in diagnostic:
        fail("restricted Lean failed for an unexpected reason: {}".format(diagnostic))

def _extract_sdk_graph(repository_ctx, config, toolchain, identity, runtime_identity):
    raw_sysroot = toolchain["sysroot"]
    lean_lib_relative = _sdk_relative_path(toolchain["leanLibDir"], raw_sysroot, "Lean library directory")
    lean = repository_ctx.path("bin/lean")
    extractor_source = repository_ctx.read(repository_ctx.attr._sdk_graph_extractor)
    if not extractor_source:
        fail("Lean SDK graph extractor source is empty")
    extractor = repository_ctx.path(repository_ctx.attr._sdk_graph_extractor)
    output = repository_ctx.path("sdk_index.bzl")
    extractor_args = [
        "--run",
        extractor,
        repository_ctx.path(lean_lib_relative),
        lean_lib_relative,
        output,
        identity,
        config.platform,
        config.sha256,
        _LEAN_GITHASH,
        runtime_identity,
    ]
    if config.platform == "x86_64-linux":
        loader = repository_ctx.path("runtime-glibc/ld-linux-x86-64.so.2")
        library_path = "{}:{}".format(
            repository_ctx.path("runtime-glibc"),
            repository_ctx.path("lib"),
        )
        command = [
            loader,
            "--library-path",
            library_path,
            "--argv0",
            lean,
            lean,
        ] + extractor_args
    else:
        command = [lean] + extractor_args
    result = repository_ctx.execute(
        command,
        environment = {
            "DYLD_LIBRARY_PATH": "",
            "HOME": "/nonexistent",
            "LD_LIBRARY_PATH": "",
            "LEAN_PATH": "",
            "LEAN_SYSROOT": "",
            "PATH": "",
        },
        timeout = 600,
    )
    if result.return_code != 0:
        fail("failed to extract pinned Lean SDK graph:\n{}\n{}".format(result.stdout, result.stderr))
    if not output.exists:
        fail("Lean SDK graph extractor did not create sdk_index.bzl")

def _lean_sdk_repository_impl(repository_ctx):
    config, manifest_label = _host_config(repository_ctx)
    manifest = json.decode(repository_ctx.read(manifest_label))
    if manifest.get("schemaVersion") != "4":
        fail("Lean SDK repository requires Lake authority schema 4")
    repository_ctx.download_and_extract(
        url = config.url,
        sha256 = config.sha256,
        stripPrefix = config.strip_prefix,
        type = "tar.zst",
    )
    runtime_identity = "darwin-native-loader"
    if config.platform == "x86_64-linux":
        runtime_identity = _copy_linux_runtime(repository_ctx)
    config_bzl, identity = _render_config(config, manifest["toolchain"], runtime_identity)
    _extract_sdk_graph(repository_ctx, config, manifest["toolchain"], identity, runtime_identity)
    _materialize_restricted_runtime(repository_ctx, config)
    if not repository_ctx.path(config.sdk_linker_path).exists:
        fail("pinned Lean SDK is missing {}".format(config.sdk_linker_path))
    repository_ctx.file("LEAN_SDK_IDENTITY", identity + "\n")
    repository_ctx.file("toolchain_config.bzl", config_bzl)
    repository_ctx.file(
        "BUILD.bazel",
        """package(default_visibility = [\"//visibility:public\"])

exports_files([
    \"LEAN_SDK_IDENTITY\",
    \"sdk_index.bzl\",
    \"{}\",
    \"bin/clang\",
    \"bin/lake\",
    \"bin/lean\",
    \"bin/leanc\",
    \"bin/llvm-ar\",
])

exports_files(
    [\"bin/leanir\"],
    visibility = [\"//visibility:private\"],
)

filegroup(
    name = \"canonical_distribution\",
    srcs = glob(
        [\"*\", \"**/*\"],
        exclude = [
            \"BUILD.bazel\",
            \"restricted/**\",
            \"restricted-unknown-module.lean\",
            \"sdk_index.bzl\",
            \"toolchain_config.bzl\",
        ],
    ),
)

filegroup(
    name = \"canonical_runtime_files\",
    srcs = glob(
        [\"lib/*\", \"runtime-glibc/*\", \"runtime-glibc/**/*\"],
        allow_empty = True,
    ),
)

filegroup(
    name = \"sdk_semantic_artifacts\",
    srcs = glob([
        \"lib/lean/**/*.ir\",
        \"lib/lean/**/*.olean\",
        \"lib/lean/**/*.olean.private\",
        \"lib/lean/**/*.olean.server\",
    ]),
)

filegroup(
    name = \"sdk_ide_artifacts\",
    srcs = glob([\"lib/lean/**/*.ilean\"]),
)

filegroup(
    name = \"restricted_runtime_files\",
    srcs = glob(
        [
            \"restricted/lib/**/*\",
            \"restricted/runtime-glibc/**/*\",
        ],
        allow_empty = True,
    ),
)

filegroup(
    name = \"restricted_compile_files\",
    srcs = [
        \"restricted/bin/cadical\",
        \"restricted/bin/lean\",
    ] + glob(
        [
            \"restricted/lib/**/*\",
            \"restricted/runtime-glibc/**/*\",
        ],
        allow_empty = True,
    ),
)

alias(
    name = \"distribution\",
    actual = \":canonical_distribution\",
)

alias(
    name = \"runtime_files\",
    actual = \":canonical_runtime_files\",
)
""".format(config.sdk_linker_path),
    )

_lean_sdk_repository = repository_rule(
    implementation = _lean_sdk_repository_impl,
    attrs = {
        "_darwin_manifest": attr.label(
            allow_single_file = True,
            default = Label("//toolchains:sdk-aarch64-darwin.json"),
        ),
        "_linux_manifest": attr.label(
            allow_single_file = True,
            default = Label("//toolchains:sdk-x86_64-linux.json"),
        ),
        "_sdk_graph_extractor": attr.label(
            allow_single_file = [".lean"],
            default = Label("//tools:ExtractSdkGraph.lean"),
        ),
    },
)

def _lean_sdk_extension_impl(_module_ctx):
    _lean_sdk_repository(name = "lean_sdk")

lean_sdk = module_extension(implementation = _lean_sdk_extension_impl)
