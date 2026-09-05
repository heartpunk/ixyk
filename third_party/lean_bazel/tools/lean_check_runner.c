#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *message) {
  fprintf(stderr, "lean-check-runner: %s\n", message);
  exit(1);
}

static void die_errno(const char *message) {
  fprintf(stderr, "lean-check-runner: %s: %s\n", message, strerror(errno));
  exit(1);
}

static const char *environment_value(const char *name) {
  const char *value = getenv(name);
  if (value == NULL) {
    fprintf(stderr, "lean-check-runner: missing required environment %s\n", name);
    exit(1);
  }
  return value;
}

static const char *required_environment(const char *name) {
  const char *value = environment_value(name);
  if (value[0] == '\0') {
    fprintf(stderr, "lean-check-runner: empty required environment %s\n", name);
    exit(1);
  }
  return value;
}

static long parse_decimal(const char *name, long minimum, long maximum) {
  const char *value = required_environment(name);
  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < minimum ||
      parsed > maximum) {
    fprintf(stderr, "lean-check-runner: invalid decimal environment %s\n", name);
    exit(1);
  }
  return parsed;
}

static int parse_presence(const char *name) {
  const char *value = required_environment(name);
  if (strcmp(value, "0") == 0) {
    return 0;
  }
  if (strcmp(value, "1") == 0) {
    return 1;
  }
  fprintf(stderr, "lean-check-runner: invalid presence environment %s\n", name);
  exit(1);
}

static char *join_path(const char *left, const char *right) {
  size_t left_length = strlen(left);
  size_t right_length = strlen(right);
  int needs_separator = left_length > 0 && left[left_length - 1] != '/';
  char *result = malloc(left_length + (size_t)needs_separator + right_length + 1);
  if (result == NULL) {
    die("out of memory while constructing a path");
  }
  memcpy(result, left, left_length);
  size_t offset = left_length;
  if (needs_separator) {
    result[offset++] = '/';
  }
  memcpy(result + offset, right, right_length);
  result[offset + right_length] = '\0';
  return result;
}

static char *current_directory(void) {
  size_t capacity = 256;
  for (;;) {
    char *buffer = malloc(capacity);
    if (buffer == NULL) {
      die("out of memory while resolving action root");
    }
    if (getcwd(buffer, capacity) != NULL) {
      return buffer;
    }
    int saved_errno = errno;
    free(buffer);
    if (saved_errno != ERANGE || capacity > (1U << 20)) {
      errno = saved_errno;
      die_errno("unable to resolve action root");
    }
    capacity *= 2;
  }
}

static char *absolute_from(const char *root, const char *path) {
  if (path[0] == '/') {
    char *copy = strdup(path);
    if (copy == NULL) {
      die("out of memory while copying an absolute path");
    }
    return copy;
  }
  return join_path(root, path);
}

static void require_directory(const char *path, const char *message) {
  struct stat status;
  if (stat(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
    die(message);
  }
}

static void write_all(int descriptor, const char *data, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(descriptor, data + offset, length - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      die_errno("unable to write output");
    }
    offset += (size_t)written;
  }
}

static char *read_capture(int descriptor, size_t *length) {
  struct stat status;
  if (fstat(descriptor, &status) != 0 || status.st_size < 0) {
    die_errno("unable to stat captured output");
  }
  size_t size = (size_t)status.st_size;
  char *content = malloc(size + 1);
  if (content == NULL) {
    die("out of memory while reading captured output");
  }
  if (lseek(descriptor, 0, SEEK_SET) < 0) {
    die_errno("unable to rewind captured output");
  }
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = read(descriptor, content + offset, size - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      free(content);
      die("captured output ended unexpectedly");
    }
    offset += (size_t)count;
  }
  content[size] = '\0';
  *length = size;
  return content;
}

static void child_failure(int descriptor, const char *stage) {
  int saved_errno = errno;
  char message[512];
  int length = snprintf(
      message,
      sizeof(message),
      "lean-check-runner: child infrastructure failure at %s: %s\n",
      stage,
      strerror(saved_errno));
  if (length > 0) {
    size_t bounded = (size_t)length < sizeof(message)
                         ? (size_t)length
                         : sizeof(message) - 1;
    size_t offset = 0;
    while (offset < bounded) {
      ssize_t written = write(descriptor, message + offset, bounded - offset);
      if (written < 0 && errno == EINTR) {
        continue;
      }
      if (written <= 0) {
        break;
      }
      offset += (size_t)written;
    }
  }
  _exit(125);
}

static char *environment_entry(const char *key, const char *value) {
  size_t key_length = strlen(key);
  size_t value_length = strlen(value);
  char *entry = malloc(key_length + value_length + 2);
  if (entry == NULL) {
    die("out of memory while constructing child environment");
  }
  memcpy(entry, key, key_length);
  entry[key_length] = '=';
  memcpy(entry + key_length + 1, value, value_length + 1);
  return entry;
}

static char **build_child_environment(
    const char *child_runfiles,
    const char *platform,
    const char *identity,
    const char *temporary_directory,
    const char *launch_cwd) {
  long catalog_count = parse_decimal("LEAN_CHECK_ENV_COUNT", 0, 65535);
  size_t baseline_count = 5;
  if (child_runfiles != NULL) {
    ++baseline_count;
  }
  if (launch_cwd != NULL) {
    ++baseline_count;
  }
  char **child_environment = calloc(
      (size_t)catalog_count + baseline_count + 1,
      sizeof(char *));
  if (child_environment == NULL) {
    die("out of memory while constructing child environment");
  }
  size_t next = 0;
  for (long index = 0; index < catalog_count; ++index) {
    char key_name[64];
    char value_name[64];
    int key_length = snprintf(
        key_name,
        sizeof(key_name),
        "LEAN_CHECK_ENV_KEY_%ld",
        index);
    int value_length = snprintf(
        value_name,
        sizeof(value_name),
        "LEAN_CHECK_ENV_VALUE_%ld",
        index);
    if (key_length <= 0 || (size_t)key_length >= sizeof(key_name) ||
        value_length <= 0 || (size_t)value_length >= sizeof(value_name)) {
      die("catalog environment control name overflow");
    }
    const char *key = required_environment(key_name);
    const char *value = getenv(value_name);
    if (value == NULL) {
      die("missing catalog environment value");
    }
    if (key[0] == '\0' || strchr(key, '=') != NULL) {
      die("invalid catalog environment key");
    }
    child_environment[next++] = environment_entry(key, value);
  }
  child_environment[next++] = environment_entry("HOME", "/nonexistent");
  child_environment[next++] = environment_entry("PATH", "");
  child_environment[next++] = environment_entry("TMPDIR", temporary_directory);
  child_environment[next++] = environment_entry("LEAN_BAZEL_PLATFORM", platform);
  child_environment[next++] = environment_entry(
      "LEAN_BAZEL_TOOLCHAIN_ID",
      identity);
  if (child_runfiles != NULL) {
    child_environment[next++] = environment_entry(
        "RUNFILES_DIR",
        child_runfiles);
  }
  if (launch_cwd != NULL) {
    child_environment[next++] = environment_entry(
        "LEAN_BAZEL_LAUNCH_CWD",
        launch_cwd);
  }
  child_environment[next] = NULL;
  return child_environment;
}

static void write_success_stamp(const char *path) {
  static const char content[] = "lean-check-success\n";
  int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (descriptor < 0) {
    die_errno("unable to create success stamp");
  }
  write_all(descriptor, content, sizeof(content) - 1);
  if (close(descriptor) != 0) {
    die_errno("unable to close success stamp");
  }
}

int main(int argc, char **argv) {
  if (argc < 1 || argv[0] == NULL || argv[0][0] == '\0') {
    die("missing argv[0]");
  }

  const char *kind = required_environment("LEAN_CHECK_KIND");
  int probe = 0;
  if (strcmp(kind, "lean_exe") == 0) {
    probe = 0;
  } else if (strcmp(kind, "lean_probe") == 0) {
    probe = 1;
  } else {
    die("invalid check kind");
  }

  const char *platform = required_environment("LEAN_CHECK_PLATFORM");
  const char *identity = required_environment("LEAN_CHECK_TOOLCHAIN_IDENTITY");
  const char *temporary_directory = required_environment("LEAN_CHECK_TMPDIR");
  const char *stamp_path = required_environment("LEAN_CHECK_STAMP");
  const char *cwd = required_environment("LEAN_CHECK_CWD");
  long expected_exit = parse_decimal("LEAN_CHECK_EXPECTED_EXIT", 0, 255);
  int expect_stdout = parse_presence("LEAN_CHECK_EXPECT_STDOUT_PRESENT");
  int expect_stderr = parse_presence("LEAN_CHECK_EXPECT_STDERR_PRESENT");
  const char *expected_stdout = getenv("LEAN_CHECK_EXPECT_STDOUT");
  const char *expected_stderr = getenv("LEAN_CHECK_EXPECT_STDERR");
  if (expected_stdout == NULL || expected_stderr == NULL) {
    die("missing expected stream environment");
  }
  long runner_argument_count = parse_decimal(
      "LEAN_CHECK_RUNNER_ARG_COUNT",
      0,
      65535);
  long argument_count = parse_decimal("LEAN_CHECK_ARG_COUNT", 0, 65535);

  char *action_root = current_directory();
  char *working_directory = absolute_from(action_root, cwd);
  char *tool_path = absolute_from(
      action_root,
      required_environment("LEAN_CHECK_TOOL"));
  if (access(tool_path, X_OK) != 0) {
    die("declared check tool is unavailable or not executable");
  }

  char *child_runfiles = NULL;
  char *source_path = NULL;
  char *setup_path = NULL;
  char *launch_cwd = NULL;
  if (probe) {
    source_path = absolute_from(
        action_root,
        required_environment("LEAN_CHECK_SOURCE"));
    setup_path = absolute_from(
        action_root,
        required_environment("LEAN_CHECK_SETUP"));
    if (strcmp(platform, "x86_64-linux") == 0) {
      /*
       * The Linux tool is a launcher that must start in the Bazel action root
       * to resolve its copied SDK and dynamic loader. Tell that launcher to
       * enter the check's requested cwd immediately before it starts Lean.
       * Darwin invokes Lean directly, so the child can chdir before execve.
       */
      launch_cwd = working_directory;
    } else if (strcmp(platform, "aarch64-darwin") != 0) {
      die("unsupported probe platform");
    }
  } else {
    child_runfiles = absolute_from(
        action_root,
        required_environment("LEAN_CHECK_TOOL_RUNFILES"));
    require_directory(
        child_runfiles,
        "declared FilesToRunProvider runfiles tree is unavailable");
  }

  size_t suffix_count = probe ? 3 : 0;
  size_t child_count = 1 + (size_t)runner_argument_count +
                       (size_t)argument_count + suffix_count;
  char **child_argv = calloc(child_count + 1, sizeof(char *));
  if (child_argv == NULL) {
    die("out of memory while constructing child argv");
  }
  size_t next = 0;
  child_argv[next++] = tool_path;
  for (long index = 0; index < runner_argument_count; ++index) {
    char name[64];
    int length = snprintf(
        name,
        sizeof(name),
        "LEAN_CHECK_RUNNER_ARG_%ld",
        index);
    if (length <= 0 || (size_t)length >= sizeof(name)) {
      die("runner argument environment name overflow");
    }
    child_argv[next++] = (char *)environment_value(name);
  }
  for (long index = 0; index < argument_count; ++index) {
    char name[64];
    int length = snprintf(name, sizeof(name), "LEAN_CHECK_ARG_%ld", index);
    if (length <= 0 || (size_t)length >= sizeof(name)) {
      die("argument environment name overflow");
    }
    child_argv[next++] = (char *)environment_value(name);
  }
  if (probe) {
    child_argv[next++] = source_path;
    child_argv[next++] = "--setup";
    child_argv[next++] = setup_path;
  }
  child_argv[next] = NULL;

  char **child_environment = build_child_environment(
      child_runfiles,
      platform,
      identity,
      temporary_directory,
      launch_cwd);

  char *stdout_template = join_path(
      temporary_directory,
      "lean-check-stdout-XXXXXX");
  char *stderr_template = join_path(
      temporary_directory,
      "lean-check-stderr-XXXXXX");
  int stdout_descriptor = mkstemp(stdout_template);
  if (stdout_descriptor < 0) {
    die_errno("unable to create stdout capture");
  }
  int stderr_descriptor = mkstemp(stderr_template);
  if (stderr_descriptor < 0) {
    die_errno("unable to create stderr capture");
  }
  int failure_pipe[2];
  if (pipe(failure_pipe) != 0 ||
      fcntl(failure_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
    die_errno("unable to create child failure pipe");
  }

  pid_t child = fork();
  if (child < 0) {
    die_errno("unable to fork check process");
  }
  if (child == 0) {
    close(failure_pipe[0]);
    if (launch_cwd == NULL && chdir(working_directory) != 0) {
      child_failure(failure_pipe[1], "chdir");
    }
    if (dup2(stdout_descriptor, STDOUT_FILENO) < 0 ||
        dup2(stderr_descriptor, STDERR_FILENO) < 0) {
      child_failure(failure_pipe[1], "dup2");
    }
    close(stdout_descriptor);
    close(stderr_descriptor);
    execve(tool_path, child_argv, child_environment);
    child_failure(failure_pipe[1], "execve");
  }

  close(failure_pipe[1]);
  int wait_status;
  while (waitpid(child, &wait_status, 0) < 0) {
    if (errno != EINTR) {
      die_errno("unable to wait for check process");
    }
  }
  char infrastructure_error[512];
  ssize_t infrastructure_length;
  do {
    infrastructure_length = read(
        failure_pipe[0],
        infrastructure_error,
        sizeof(infrastructure_error));
  } while (infrastructure_length < 0 && errno == EINTR);
  close(failure_pipe[0]);

  size_t stdout_length;
  size_t stderr_length;
  char *stdout_content = read_capture(stdout_descriptor, &stdout_length);
  char *stderr_content = read_capture(stderr_descriptor, &stderr_length);
  close(stdout_descriptor);
  close(stderr_descriptor);
  unlink(stdout_template);
  unlink(stderr_template);

  if (stdout_length > 0) {
    write_all(STDOUT_FILENO, stdout_content, stdout_length);
  }
  if (stderr_length > 0) {
    write_all(STDERR_FILENO, stderr_content, stderr_length);
  }
  if (infrastructure_length < 0) {
    die_errno("unable to read child failure status");
  }
  if (infrastructure_length > 0) {
    write_all(STDERR_FILENO, infrastructure_error, (size_t)infrastructure_length);
    return 1;
  }

  int mismatch = 0;
  if (!WIFEXITED(wait_status)) {
    fprintf(
        stderr,
        "lean-check-runner: exit mismatch: expected %ld, child terminated by signal %d\n",
        expected_exit,
        WIFSIGNALED(wait_status) ? WTERMSIG(wait_status) : -1);
    mismatch = 1;
  } else if (WEXITSTATUS(wait_status) != expected_exit) {
    fprintf(
        stderr,
        "lean-check-runner: exit mismatch: expected %ld, got %d\n",
        expected_exit,
        WEXITSTATUS(wait_status));
    mismatch = 1;
  }
  size_t expected_stdout_length = strlen(expected_stdout);
  if (expect_stdout &&
      (stdout_length != expected_stdout_length ||
       memcmp(stdout_content, expected_stdout, stdout_length) != 0)) {
    fprintf(
        stderr,
        "lean-check-runner: stdout mismatch: expected %zu bytes, got %zu bytes\n",
        expected_stdout_length,
        stdout_length);
    mismatch = 1;
  }
  size_t expected_stderr_length = strlen(expected_stderr);
  if (expect_stderr &&
      (stderr_length != expected_stderr_length ||
       memcmp(stderr_content, expected_stderr, stderr_length) != 0)) {
    fprintf(
        stderr,
        "lean-check-runner: stderr mismatch: expected %zu bytes, got %zu bytes\n",
        expected_stderr_length,
        stderr_length);
    mismatch = 1;
  }
  if (mismatch) {
    return 1;
  }
  write_success_stamp(stamp_path);
  return 0;
}
