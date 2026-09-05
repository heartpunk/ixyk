#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct mapping {
  char *logical;
  char *physical;
};

struct mapping_array {
  struct mapping *items;
  size_t count;
  size_t capacity;
};

static void diagnostic(const char *format, ...) {
  char buffer[1024];
  va_list arguments;
  va_start(arguments, format);
  int length = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  if (length < 0) {
    static const char fallback[] = "projection-export-runner: diagnostic failure\n";
    size_t offset = 0;
    while (offset < sizeof(fallback) - 1U) {
      ssize_t written =
          write(STDERR_FILENO, fallback + offset, sizeof(fallback) - 1U - offset);
      if (written > 0) {
        offset += (size_t)written;
      } else if (written < 0 && errno == EINTR) {
        continue;
      } else {
        break;
      }
    }
    return;
  }
  size_t bounded = (size_t)length < sizeof(buffer)
                       ? (size_t)length
                       : sizeof(buffer) - 1;
  size_t offset = 0;
  while (offset < bounded) {
    ssize_t written = write(STDERR_FILENO, buffer + offset, bounded - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return;
    }
    offset += (size_t)written;
  }
}

static void fail(const char *message) {
  diagnostic("projection-export-runner: %s\n", message);
  exit(1);
}

static void fail_errno(const char *message) {
  int saved_errno = errno;
  diagnostic(
      "projection-export-runner: %s: %s\n",
      message,
      strerror(saved_errno));
  exit(1);
}

static const char *control(const char *name, int allow_empty) {
  const char *value = getenv(name);
  if (value == NULL || (!allow_empty && value[0] == '\0')) {
    diagnostic(
        "projection-export-runner: missing required control %.200s\n",
        name);
    exit(1);
  }
  return value;
}

static char *duplicate_bytes(const unsigned char *bytes, size_t length) {
  char *result = malloc(length + 1);
  if (result == NULL) {
    fail("out of memory while parsing the input map");
  }
  memcpy(result, bytes, length);
  result[length] = '\0';
  return result;
}

static char *current_directory(void) {
  size_t capacity = 256;
  for (;;) {
    char *buffer = malloc(capacity);
    if (buffer == NULL) {
      fail("out of memory while resolving the action root");
    }
    if (getcwd(buffer, capacity) != NULL) {
      return buffer;
    }
    int saved_errno = errno;
    free(buffer);
    if (saved_errno != ERANGE || capacity > (1U << 20)) {
      errno = saved_errno;
      fail_errno("unable to resolve the action root");
    }
    capacity *= 2;
  }
}

static char *join_path(const char *left, const char *right) {
  size_t left_length = strlen(left);
  size_t right_length = strlen(right);
  int separator = left_length > 0 && left[left_length - 1] != '/';
  if (left_length > SIZE_MAX - right_length - (size_t)separator - 1) {
    fail("path length overflow");
  }
  char *result = malloc(left_length + (size_t)separator + right_length + 1);
  if (result == NULL) {
    fail("out of memory while resolving a path");
  }
  memcpy(result, left, left_length);
  size_t offset = left_length;
  if (separator) {
    result[offset++] = '/';
  }
  memcpy(result + offset, right, right_length);
  result[offset + right_length] = '\0';
  return result;
}

static char *resolve_path(const char *action_root, const char *path) {
  if (path[0] == '/') {
    char *copy = strdup(path);
    if (copy == NULL) {
      fail("out of memory while copying an absolute path");
    }
    return copy;
  }
  return join_path(action_root, path);
}

static int stat_retry(const char *path, struct stat *status) {
  int result;
  do {
    result = stat(path, status);
  } while (result != 0 && errno == EINTR);
  return result;
}

static int fstat_retry(int descriptor, struct stat *status) {
  int result;
  do {
    result = fstat(descriptor, status);
  } while (result != 0 && errno == EINTR);
  return result;
}

static int access_retry(const char *path, int mode) {
  int result;
  do {
    result = access(path, mode);
  } while (result != 0 && errno == EINTR);
  return result;
}

static void require_directory(const char *path, const char *description) {
  struct stat status;
  if (stat_retry(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
    diagnostic(
        "projection-export-runner: %s is not a directory: %.300s\n",
        description,
        path);
    exit(1);
  }
}

static void mkdir_one(const char *path, int allow_existing) {
  int result;
  do {
    result = mkdir(path, 0777);
  } while (result != 0 && errno == EINTR);
  if (result == 0) {
    return;
  }
  if (allow_existing && errno == EEXIST) {
    struct stat status;
    if (stat_retry(path, &status) == 0 && S_ISDIR(status.st_mode)) {
      return;
    }
  }
  diagnostic(
      "projection-export-runner: unable to create directory %.300s: %s\n",
      path,
      strerror(errno));
  exit(1);
}

static void prepare_output_directory(const char *path) {
  int result;
  do {
    result = mkdir(path, 0777);
  } while (result != 0 && errno == EINTR);
  if (result == 0) {
    return;
  }
  if (errno != EEXIST) {
    diagnostic(
        "projection-export-runner: unable to create output directory %.300s: %s\n",
        path,
        strerror(errno));
    exit(1);
  }

  DIR *directory = opendir(path);
  if (directory == NULL) {
    diagnostic(
        "projection-export-runner: declared output is not a readable directory %.300s: %s\n",
        path,
        strerror(errno));
    exit(1);
  }
  errno = 0;
  for (;;) {
    struct dirent *entry = readdir(directory);
    if (entry == NULL) {
      break;
    }
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      diagnostic(
          "projection-export-runner: declared output directory is not empty: %.300s\n",
          path);
      (void)closedir(directory);
      exit(1);
    }
    errno = 0;
  }
  if (errno != 0) {
    int saved_errno = errno;
    (void)closedir(directory);
    diagnostic(
        "projection-export-runner: unable to inspect output directory %.300s: %s\n",
        path,
        strerror(saved_errno));
    exit(1);
  }
  if (closedir(directory) != 0) {
    diagnostic(
        "projection-export-runner: unable to close output directory %.300s: %s\n",
        path,
        strerror(errno));
    exit(1);
  }
}

static void create_parent_directories(const char *path) {
  char *copy = strdup(path);
  if (copy == NULL) {
    fail("out of memory while creating parent directories");
  }
  for (size_t index = 1; copy[index] != '\0'; ++index) {
    if (copy[index] != '/') {
      continue;
    }
    copy[index] = '\0';
    if (copy[0] != '\0') {
      mkdir_one(copy, 1);
    }
    copy[index] = '/';
  }
  free(copy);
}

static int open_readonly(const char *path) {
  int descriptor;
  do {
    descriptor = open(path, O_RDONLY);
  } while (descriptor < 0 && errno == EINTR);
  return descriptor;
}

static void write_all(int descriptor, const unsigned char *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(descriptor, bytes + offset, length - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      fail_errno("unable to write staged file bytes");
    }
    offset += (size_t)written;
  }
}

static unsigned char *read_map(const char *path, size_t *length) {
  int descriptor = open_readonly(path);
  if (descriptor < 0) {
    fail_errno("unable to open the projection input map");
  }
  struct stat status;
  if (fstat_retry(descriptor, &status) != 0) {
    fail_errno("unable to stat the projection input map");
  }
  if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
      (uintmax_t)status.st_size > (uintmax_t)(SIZE_MAX - 1)) {
    fail("projection input map must be a bounded regular file");
  }
  size_t size = (size_t)status.st_size;
  unsigned char *bytes = malloc(size + 1);
  if (bytes == NULL) {
    fail("out of memory while reading the projection input map");
  }
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = read(descriptor, bytes + offset, size - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      fail_errno("unable to read the projection input map");
    }
    if (count == 0) {
      fail("projection input map ended unexpectedly");
    }
    offset += (size_t)count;
  }
  if (close(descriptor) != 0) {
    fail_errno("unable to close the projection input map");
  }
  bytes[size] = '\0';
  *length = size;
  return bytes;
}

static int valid_utf8(const unsigned char *bytes, size_t length) {
  size_t index = 0;
  while (index < length) {
    unsigned char first = bytes[index++];
    if (first <= 0x7f) {
      continue;
    }
    if (first >= 0xc2 && first <= 0xdf) {
      if (index >= length || bytes[index] < 0x80 || bytes[index] > 0xbf) {
        return 0;
      }
      ++index;
      continue;
    }
    if (first == 0xe0) {
      if (index + 1 >= length || bytes[index] < 0xa0 || bytes[index] > 0xbf ||
          bytes[index + 1] < 0x80 || bytes[index + 1] > 0xbf) {
        return 0;
      }
      index += 2;
      continue;
    }
    if ((first >= 0xe1 && first <= 0xec) ||
        (first >= 0xee && first <= 0xef)) {
      if (index + 1 >= length || bytes[index] < 0x80 || bytes[index] > 0xbf ||
          bytes[index + 1] < 0x80 || bytes[index + 1] > 0xbf) {
        return 0;
      }
      index += 2;
      continue;
    }
    if (first == 0xed) {
      if (index + 1 >= length || bytes[index] < 0x80 || bytes[index] > 0x9f ||
          bytes[index + 1] < 0x80 || bytes[index + 1] > 0xbf) {
        return 0;
      }
      index += 2;
      continue;
    }
    if (first == 0xf0) {
      if (index + 2 >= length || bytes[index] < 0x90 || bytes[index] > 0xbf ||
          bytes[index + 1] < 0x80 || bytes[index + 1] > 0xbf ||
          bytes[index + 2] < 0x80 || bytes[index + 2] > 0xbf) {
        return 0;
      }
      index += 3;
      continue;
    }
    if (first >= 0xf1 && first <= 0xf3) {
      if (index + 2 >= length || bytes[index] < 0x80 || bytes[index] > 0xbf ||
          bytes[index + 1] < 0x80 || bytes[index + 1] > 0xbf ||
          bytes[index + 2] < 0x80 || bytes[index + 2] > 0xbf) {
        return 0;
      }
      index += 3;
      continue;
    }
    if (first == 0xf4) {
      if (index + 2 >= length || bytes[index] < 0x80 || bytes[index] > 0x8f ||
          bytes[index + 1] < 0x80 || bytes[index + 1] > 0xbf ||
          bytes[index + 2] < 0x80 || bytes[index + 2] > 0xbf) {
        return 0;
      }
      index += 3;
      continue;
    }
    return 0;
  }
  return 1;
}

static int valid_logical_path(const unsigned char *path, size_t length) {
  if (length == 0 || path[0] == '/') {
    return 0;
  }
  size_t component_start = 0;
  for (size_t index = 0; index <= length; ++index) {
    if (index < length && path[index] == '\\') {
      return 0;
    }
    if (index < length && path[index] != '/') {
      continue;
    }
    size_t component_length = index - component_start;
    if (component_length == 0 ||
        (component_length == 1 && path[component_start] == '.') ||
        (component_length == 2 && path[component_start] == '.' &&
         path[component_start + 1] == '.')) {
      return 0;
    }
    component_start = index + 1;
  }
  return 1;
}

static void append_mapping(
    struct mapping_array *mappings,
    char *logical,
    char *physical) {
  for (size_t index = 0; index < mappings->count; ++index) {
    if (strcmp(mappings->items[index].logical, logical) == 0) {
      diagnostic(
          "projection-export-runner: duplicate logical path %.300s\n",
          logical);
      exit(1);
    }
  }
  if (mappings->count == mappings->capacity) {
    size_t capacity = mappings->capacity == 0 ? 16 : mappings->capacity * 2;
    if (capacity < mappings->capacity ||
        capacity > SIZE_MAX / sizeof(struct mapping)) {
      fail("projection input map is too large");
    }
    struct mapping *items = realloc(
        mappings->items,
        capacity * sizeof(struct mapping));
    if (items == NULL) {
      fail("out of memory while storing projection input mappings");
    }
    mappings->items = items;
    mappings->capacity = capacity;
  }
  mappings->items[mappings->count].logical = logical;
  mappings->items[mappings->count].physical = physical;
  ++mappings->count;
}

static struct mapping_array parse_map(
    const unsigned char *bytes,
    size_t length) {
  struct mapping_array mappings = {0};
  if (length != 0 && bytes[length - 1] != '\n') {
    fail("projection input map must end every record with LF");
  }
  size_t line_start = 0;
  for (size_t index = 0; index < length; ++index) {
    if (bytes[index] == '\0' || bytes[index] == '\r') {
      fail("projection input map contains a malformed newline or NUL byte");
    }
    if (bytes[index] != '\n') {
      continue;
    }
    size_t line_length = index - line_start;
    if (line_length == 0) {
      fail("projection input map contains an empty record");
    }
    size_t tab = SIZE_MAX;
    for (size_t cursor = line_start; cursor < index; ++cursor) {
      if (bytes[cursor] != '\t') {
        continue;
      }
      if (tab != SIZE_MAX) {
        fail("projection input map record contains multiple tabs");
      }
      tab = cursor;
    }
    if (tab == SIZE_MAX || tab == line_start || tab + 1 == index) {
      fail("projection input map record must be logical<TAB>physical");
    }
    size_t logical_length = tab - line_start;
    size_t physical_length = index - tab - 1;
    if (!valid_utf8(bytes + line_start, logical_length) ||
        !valid_utf8(bytes + tab + 1, physical_length)) {
      fail("projection input map must be valid UTF-8");
    }
    if (!valid_logical_path(bytes + line_start, logical_length)) {
      fail("projection input map contains an invalid logical path");
    }
    append_mapping(
        &mappings,
        duplicate_bytes(bytes + line_start, logical_length),
        duplicate_bytes(bytes + tab + 1, physical_length));
    line_start = index + 1;
  }
  return mappings;
}

static void copy_file_bytes(const char *source, const char *destination) {
  int source_descriptor = open_readonly(source);
  if (source_descriptor < 0) {
    diagnostic(
        "projection-export-runner: unable to open declared input %.300s: %s\n",
        source,
        strerror(errno));
    exit(1);
  }
  struct stat status;
  if (fstat_retry(source_descriptor, &status) != 0 ||
      !S_ISREG(status.st_mode)) {
    fail("declared projection input is not a regular file");
  }
  create_parent_directories(destination);
  int destination_descriptor;
  do {
    destination_descriptor = open(
        destination,
        O_WRONLY | O_CREAT | O_EXCL,
        0666);
  } while (destination_descriptor < 0 && errno == EINTR);
  if (destination_descriptor < 0) {
    diagnostic(
        "projection-export-runner: unable to create staged file %.300s: %s\n",
        destination,
        strerror(errno));
    exit(1);
  }
  unsigned char buffer[65536];
  for (;;) {
    ssize_t count = read(source_descriptor, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      fail_errno("unable to read a declared projection input");
    }
    if (count == 0) {
      break;
    }
    write_all(destination_descriptor, buffer, (size_t)count);
  }
  if (close(source_descriptor) != 0) {
    fail_errno("unable to close a declared projection input");
  }
  if (close(destination_descriptor) != 0) {
    fail_errno("unable to close a staged projection input");
  }
}

static char *environment_entry(const char *key, const char *value) {
  size_t key_length = strlen(key);
  size_t value_length = strlen(value);
  if (key_length > SIZE_MAX - value_length - 2) {
    fail("child environment length overflow");
  }
  char *entry = malloc(key_length + value_length + 2);
  if (entry == NULL) {
    fail("out of memory while constructing child environment");
  }
  memcpy(entry, key, key_length);
  entry[key_length] = '=';
  memcpy(entry + key_length + 1, value, value_length + 1);
  return entry;
}

int main(void) {
  const char *map_control = control("LEAN_PROJECTION_INPUT_MAP", 0);
  const char *staged_control = control("LEAN_PROJECTION_STAGED_WORKSPACE", 0);
  const char *manifest_control = control("LEAN_PROJECTION_MANIFEST", 0);
  const char *exporter_control = control("LEAN_PROJECTION_EXPORTER", 0);
  const char *runfiles_control = control(
      "LEAN_PROJECTION_EXPORTER_RUNFILES",
      1);
  const char *sysroot_control = control("LEAN_PROJECTION_LEAN_SYSROOT", 0);
  const char *lean_lib_control = control("LEAN_PROJECTION_LEAN_LIB_DIR", 0);
  const char *platform = control("LEAN_PROJECTION_PLATFORM", 0);
  const char *toolchain_identity = control(
      "LEAN_PROJECTION_TOOLCHAIN_ID",
      0);

  char *action_root = current_directory();
  char *map_path = resolve_path(action_root, map_control);
  char *staged_workspace = resolve_path(action_root, staged_control);
  char *manifest = resolve_path(action_root, manifest_control);
  char *exporter = resolve_path(action_root, exporter_control);
  char *lean_sysroot = resolve_path(action_root, sysroot_control);
  char *lean_lib_dir = resolve_path(action_root, lean_lib_control);
  char *exporter_runfiles = runfiles_control[0] == '\0'
                                ? NULL
                                : resolve_path(action_root, runfiles_control);

  size_t map_length;
  unsigned char *map_bytes = read_map(map_path, &map_length);
  struct mapping_array mappings = parse_map(map_bytes, map_length);

  create_parent_directories(staged_workspace);
  prepare_output_directory(staged_workspace);
  for (size_t index = 0; index < mappings.count; ++index) {
    char *source = resolve_path(action_root, mappings.items[index].physical);
    char *destination = join_path(
        staged_workspace,
        mappings.items[index].logical);
    copy_file_bytes(source, destination);
    free(source);
    free(destination);
  }

  create_parent_directories(manifest);
  require_directory(lean_sysroot, "Lean sysroot");
  require_directory(lean_lib_dir, "Lean library root");
  if (access_retry(exporter, X_OK) != 0) {
    fail("declared projection exporter is unavailable or not executable");
  }
  if (exporter_runfiles != NULL) {
    require_directory(exporter_runfiles, "exporter runfiles root");
  }

  char *child_environment[8];
  size_t environment_count = 0;
  child_environment[environment_count++] = environment_entry(
      "HOME",
      "/nonexistent");
  child_environment[environment_count++] = environment_entry("PATH", "");
  child_environment[environment_count++] = environment_entry("TMPDIR", "/tmp");
  child_environment[environment_count++] = environment_entry(
      "LEAN_PATH",
      lean_lib_dir);
  child_environment[environment_count++] = environment_entry(
      "LEAN_BAZEL_PLATFORM",
      platform);
  child_environment[environment_count++] = environment_entry(
      "LEAN_BAZEL_TOOLCHAIN_ID",
      toolchain_identity);
  if (exporter_runfiles != NULL) {
    child_environment[environment_count++] = environment_entry(
        "RUNFILES_DIR",
        exporter_runfiles);
  }
  child_environment[environment_count] = NULL;

  char *child_argv[] = {
      exporter,
      "--lean-sysroot",
      lean_sysroot,
      "--workspace",
      staged_workspace,
      "--use-staged-packages",
      manifest,
      NULL,
  };

  pid_t child;
  do {
    child = fork();
  } while (child < 0 && errno == EINTR);
  if (child < 0) {
    fail_errno("unable to fork the projection exporter");
  }
  if (child == 0) {
    do {
      execve(exporter, child_argv, child_environment);
    } while (errno == EINTR);
    int saved_errno = errno;
    diagnostic(
        "projection-export-runner: unable to exec exporter: %s\n",
        strerror(saved_errno));
    _exit(127);
  }

  int status;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0) {
    fail_errno("unable to wait for the projection exporter");
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    int signal_number = WTERMSIG(status);
    diagnostic(
        "projection-export-runner: exporter terminated by signal %d\n",
        signal_number);
    return 128 + signal_number;
  }
  fail("projection exporter ended without an exit status");
  return 1;
}
