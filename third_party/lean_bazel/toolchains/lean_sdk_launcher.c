/* Freestanding x86_64 Linux launcher for upstream Lean SDK binaries on NixOS. */

typedef unsigned long usize;

#ifndef LEAN_BINARY_RUNTIME_TRAMPOLINE
static char working_directory[4096];
#endif
static char sdk_root[4096];
static char target_path[4096];
static char loader_path[4096];
static char library_path[8192];
static char *next_argv[4096];

static long syscall1(long number, long arg1) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg1;
  __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi) : "rcx", "r11", "memory");
  return rax;
}

static long syscall3(long number, long arg1, long arg2, long arg3) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg1;
  register long rsi __asm__("rsi") = arg2;
  register long rdx __asm__("rdx") = arg3;
  __asm__ volatile(
      "syscall"
      : "+r"(rax)
      : "r"(rdi), "r"(rsi), "r"(rdx)
      : "rcx", "r11", "memory");
  return rax;
}

static usize string_length(const char *value) {
  usize length = 0;
  while (value[length] != '\0') {
    ++length;
  }
  return length;
}

__attribute__((noreturn)) static void fail(void);

static usize append_checked(
    char *destination,
    usize capacity,
    usize offset,
    const char *source) {
  usize index = 0;
  while (source[index] != '\0') {
    if (offset + 1 >= capacity) {
      fail();
    }
    destination[offset++] = source[index++];
  }
  destination[offset] = '\0';
  return offset;
}

static const char *find_environment(char **envp, const char *name) {
  usize name_length = string_length(name);
  for (usize entry_index = 0; envp[entry_index] != (char *)0; ++entry_index) {
    const char *entry = envp[entry_index];
    usize index = 0;
    while (index < name_length && entry[index] == name[index]) {
      ++index;
    }
    if (index == name_length && entry[index] == '=') {
      return &entry[index + 1];
    }
  }
  return (const char *)0;
}

#ifdef LEAN_SDK_LINKER_TRAMPOLINE
static int is_declared_relative_path(const char *path) {
  if (path == (const char *)0 || path[0] == '\0' || path[0] == '/') {
    return 0;
  }
  usize component_start = 0;
  for (usize index = 0;; ++index) {
    if (path[index] == '/' || path[index] == '\0') {
      usize component_length = index - component_start;
      if (component_length == 0 ||
          (component_length == 1 && path[component_start] == '.') ||
          (component_length == 2 && path[component_start] == '.' &&
           path[component_start + 1] == '.')) {
        return 0;
      }
      if (path[index] == '\0') {
        return 1;
      }
      component_start = index + 1;
    }
  }
}
#endif

__attribute__((noreturn)) static void fail(void) {
#ifdef LEAN_SDK_LINKER_TRAMPOLINE
  static const char message[] = "lean-sdk-linker: unable to start SDK linker\n";
#elif defined(LEAN_BINARY_RUNTIME_TRAMPOLINE)
  static const char message[] = "lean-binary-runner: unable to start binary\n";
#else
  static const char message[] = "lean-sdk-launcher: unable to start SDK tool\n";
#endif
  syscall3(1, 2, (long)message, sizeof(message) - 1);
  syscall1(60, 127);
  __builtin_unreachable();
}

#ifdef LEAN_BINARY_RUNTIME_TRAMPOLINE
__attribute__((noreturn)) static void fail_manifest_runfiles(void) {
  static const char message[] =
      "lean-binary-runner: manifest-only runfiles are unsupported\n";
  syscall3(1, 2, (long)message, sizeof(message) - 1);
  syscall1(60, 127);
  __builtin_unreachable();
}
#endif

#if !defined(LEAN_SDK_LINKER_TRAMPOLINE) && \
    !defined(LEAN_BINARY_RUNTIME_TRAMPOLINE)
__attribute__((noreturn)) void launcher_main(long *initial_stack) {
  static const char launch_cwd_variable[] = "LEAN_BAZEL_LAUNCH_CWD";
  long argc = initial_stack[0];
  char **argv = (char **)&initial_stack[1];
  char **envp = &argv[argc + 1];
  const char *launch_cwd = find_environment(envp, launch_cwd_variable);
  if (argc < 3 || string_length(argv[1]) == 0 || string_length(argv[2]) == 0 ||
      argv[1][0] == '/') {
    fail();
  }

  long cwd_length = syscall3(
      79,
      (long)working_directory,
      sizeof(working_directory),
      0);
  if (cwd_length <= 0 || cwd_length >= (long)sizeof(working_directory)) {
    fail();
  }

  usize offset = append_checked(
      sdk_root, sizeof(sdk_root), 0, working_directory);
  offset = append_checked(sdk_root, sizeof(sdk_root), offset, "/");
  append_checked(sdk_root, sizeof(sdk_root), offset, argv[1]);

  offset = append_checked(target_path, sizeof(target_path), 0, sdk_root);
  offset = append_checked(
      target_path, sizeof(target_path), offset, "/bin/");
  append_checked(target_path, sizeof(target_path), offset, argv[2]);

  offset = append_checked(loader_path, sizeof(loader_path), 0, sdk_root);
  append_checked(
      loader_path,
      sizeof(loader_path),
      offset,
      "/runtime-glibc/ld-linux-x86-64.so.2");

  offset = append_checked(library_path, sizeof(library_path), 0, sdk_root);
  offset = append_checked(
      library_path, sizeof(library_path), offset, "/runtime-glibc:");
  offset = append_checked(
      library_path, sizeof(library_path), offset, sdk_root);
  append_checked(library_path, sizeof(library_path), offset, "/lib");

  usize next_argc = 0;
  next_argv[next_argc++] = loader_path;
  next_argv[next_argc++] = "--library-path";
  next_argv[next_argc++] = library_path;
  next_argv[next_argc++] = target_path;
  for (long index = 3; index < argc; ++index) {
    if (next_argc + 1 >= sizeof(next_argv) / sizeof(next_argv[0])) {
      fail();
    }
    next_argv[next_argc++] = argv[index];
  }
  next_argv[next_argc] = (char *)0;

  if (launch_cwd != (const char *)0) {
    if (launch_cwd[0] != '/' || syscall1(80, (long)launch_cwd) != 0) {
      fail();
    }
  }

  syscall3(59, (long)loader_path, (long)next_argv, (long)envp);
  fail();
}
#elif defined(LEAN_SDK_LINKER_TRAMPOLINE)
__attribute__((noreturn)) void linker_main(long *initial_stack) {
  static const char sdk_root_variable[] = "LEAN_BAZEL_LINKER_SDK_ROOT";
  long argc = initial_stack[0];
  char **argv = (char **)&initial_stack[1];
  char **envp = &argv[argc + 1];
  const char *relative_sdk_root = find_environment(envp, sdk_root_variable);
  if (argc < 1 || !is_declared_relative_path(relative_sdk_root)) {
    fail();
  }

  long cwd_length = syscall3(
      79,
      (long)working_directory,
      sizeof(working_directory),
      0);
  if (cwd_length <= 0 || cwd_length >= (long)sizeof(working_directory)) {
    fail();
  }

  usize offset = append_checked(
      sdk_root,
      sizeof(sdk_root),
      0,
      working_directory);
  offset = append_checked(sdk_root, sizeof(sdk_root), offset, "/");
  append_checked(sdk_root, sizeof(sdk_root), offset, relative_sdk_root);

  offset = append_checked(target_path, sizeof(target_path), 0, sdk_root);
  offset = append_checked(target_path, sizeof(target_path), offset, "/bin/");
  append_checked(target_path, sizeof(target_path), offset, "ld.lld");

  offset = append_checked(loader_path, sizeof(loader_path), 0, sdk_root);
  append_checked(
      loader_path,
      sizeof(loader_path),
      offset,
      "/runtime-glibc/ld-linux-x86-64.so.2");

  offset = append_checked(library_path, sizeof(library_path), 0, sdk_root);
  offset = append_checked(
      library_path,
      sizeof(library_path),
      offset,
      "/runtime-glibc:");
  offset = append_checked(library_path, sizeof(library_path), offset, sdk_root);
  append_checked(library_path, sizeof(library_path), offset, "/lib");

  usize next_argc = 0;
  next_argv[next_argc++] = loader_path;
  next_argv[next_argc++] = "--library-path";
  next_argv[next_argc++] = library_path;
  next_argv[next_argc++] = "--argv0";
  next_argv[next_argc++] = argv[0];
  next_argv[next_argc++] = target_path;
  for (long index = 1; index < argc; ++index) {
    if (next_argc + 1 >= sizeof(next_argv) / sizeof(next_argv[0])) {
      fail();
    }
    next_argv[next_argc++] = argv[index];
  }
  next_argv[next_argc] = (char *)0;

  syscall3(59, (long)loader_path, (long)next_argv, (long)envp);
  fail();
}
#else
__attribute__((noreturn)) void binary_main(long *initial_stack) {
  static const char runfiles_directory_variable[] = "RUNFILES_DIR";
  static const char runfiles_manifest_variable[] = "RUNFILES_MANIFEST_FILE";
  long argc = initial_stack[0];
  char **argv = (char **)&initial_stack[1];
  char **envp = &argv[argc + 1];
  if (argc < 1 || argv[0][0] == '\0') {
    fail();
  }

  const char *runfiles_directory = find_environment(
      envp,
      runfiles_directory_variable);
  const char *runfiles_manifest = find_environment(
      envp,
      runfiles_manifest_variable);
  usize offset;
  if (runfiles_directory != (const char *)0 &&
      runfiles_directory[0] != '\0') {
    offset = append_checked(sdk_root, sizeof(sdk_root), 0, runfiles_directory);
    append_checked(sdk_root, sizeof(sdk_root), offset, "/lean-sdk");
    offset = append_checked(
        target_path,
        sizeof(target_path),
        0,
        runfiles_directory);
    append_checked(
        target_path,
        sizeof(target_path),
        offset,
        "/lean-binary/payload");
  } else {
    if (runfiles_manifest != (const char *)0 &&
        runfiles_manifest[0] != '\0') {
      fail_manifest_runfiles();
    }
    offset = append_checked(sdk_root, sizeof(sdk_root), 0, argv[0]);
    append_checked(sdk_root, sizeof(sdk_root), offset, ".runfiles/lean-sdk");
    offset = append_checked(target_path, sizeof(target_path), 0, argv[0]);
    append_checked(
        target_path,
        sizeof(target_path),
        offset,
        ".runfiles/lean-binary/payload");
  }

  offset = append_checked(loader_path, sizeof(loader_path), 0, sdk_root);
  append_checked(
      loader_path,
      sizeof(loader_path),
      offset,
      "/runtime-glibc/ld-linux-x86-64.so.2");

  offset = append_checked(library_path, sizeof(library_path), 0, sdk_root);
  offset = append_checked(
      library_path,
      sizeof(library_path),
      offset,
      "/runtime-glibc:");
  offset = append_checked(library_path, sizeof(library_path), offset, sdk_root);
  append_checked(library_path, sizeof(library_path), offset, "/lib");

  usize next_argc = 0;
  next_argv[next_argc++] = loader_path;
  next_argv[next_argc++] = "--library-path";
  next_argv[next_argc++] = library_path;
  next_argv[next_argc++] = "--argv0";
  next_argv[next_argc++] = argv[0];
  next_argv[next_argc++] = target_path;
  for (long index = 1; index < argc; ++index) {
    if (next_argc + 1 >= sizeof(next_argv) / sizeof(next_argv[0])) {
      fail();
    }
    next_argv[next_argc++] = argv[index];
  }
  next_argv[next_argc] = (char *)0;

  syscall3(59, (long)loader_path, (long)next_argv, (long)envp);
  fail();
}
#endif

#if !defined(LEAN_SDK_LINKER_TRAMPOLINE) && \
    !defined(LEAN_BINARY_RUNTIME_TRAMPOLINE)
__asm__(
    ".global _start\n"
    "_start:\n"
    "mov %rsp, %rdi\n"
    "and $-16, %rsp\n"
    "call launcher_main\n");
#elif defined(LEAN_SDK_LINKER_TRAMPOLINE)
__asm__(
    ".global _start\n"
    "_start:\n"
    "mov %rsp, %rdi\n"
    "and $-16, %rsp\n"
    "call linker_main\n");
#else
__asm__(
    ".global _start\n"
    "_start:\n"
    "mov %rsp, %rdi\n"
    "and $-16, %rsp\n"
    "call binary_main\n");
#endif
