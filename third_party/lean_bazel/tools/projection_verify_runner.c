#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define IO_BUFFER_SIZE 65536U
#define MAX_ENVIRONMENT_VALUE 65536U
#define MAX_SOURCE_COUNT 65535U
#define SHA256_BLOCK_SIZE 64U
#define SHA256_DIGEST_SIZE 32U
#define SHA256_MAX_BYTES (UINT64_MAX / UINT64_C(8))

struct sha256_context {
  uint32_t state[8];
  uint64_t total_bytes;
  unsigned char block[SHA256_BLOCK_SIZE];
  size_t block_length;
};

struct byte_buffer {
  char *data;
  size_t length;
  size_t capacity;
};

struct compare_reader {
  int descriptor;
  unsigned char buffer[IO_BUFFER_SIZE];
  size_t position;
  size_t length;
  int eof;
};

static char *metadata_output;
static char *stamp_output;
static char *metadata_temporary;
static char *stamp_temporary;
static int outputs_committed;

static void remove_if_exists(const char *path);

static void cleanup_outputs(void) {
  if (outputs_committed) {
    return;
  }
  if (metadata_temporary != NULL) {
    int result;
    do {
      result = unlink(metadata_temporary);
    } while (result != 0 && errno == EINTR);
  }
  if (stamp_temporary != NULL) {
    int result;
    do {
      result = unlink(stamp_temporary);
    } while (result != 0 && errno == EINTR);
  }
  if (metadata_output != NULL) {
    int result;
    do {
      result = unlink(metadata_output);
    } while (result != 0 && errno == EINTR);
  }
  if (stamp_output != NULL) {
    int result;
    do {
      result = unlink(stamp_output);
    } while (result != 0 && errno == EINTR);
  }
}

static _Noreturn void die(const char *message) {
  fprintf(stderr, "projection-verify-runner: %s\n", message);
  exit(1);
}

static _Noreturn void die_errno(const char *message) {
  int saved_errno = errno;
  fprintf(
      stderr,
      "projection-verify-runner: %s: %s\n",
      message,
      strerror(saved_errno));
  exit(1);
}

static size_t checked_string_length(const char *value, const char *description) {
  size_t length = 0;
  while (length <= MAX_ENVIRONMENT_VALUE && value[length] != '\0') {
    ++length;
  }
  if (length > MAX_ENVIRONMENT_VALUE) {
    fprintf(
        stderr,
        "projection-verify-runner: %s exceeds %u bytes\n",
        description,
        (unsigned int)MAX_ENVIRONMENT_VALUE);
    exit(1);
  }
  return length;
}

static const char *required_environment(const char *name) {
  const char *value = getenv(name);
  if (value == NULL || value[0] == '\0') {
    fprintf(
        stderr,
        "projection-verify-runner: missing required environment %s\n",
        name);
    exit(1);
  }
  (void)checked_string_length(value, name);
  return value;
}

static size_t parse_count(const char *name) {
  const char *value = required_environment(name);
  size_t result = 0;
  const unsigned char *cursor = (const unsigned char *)value;
  while (*cursor != '\0') {
    if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9') {
      fprintf(
          stderr,
          "projection-verify-runner: invalid decimal environment %s\n",
          name);
      exit(1);
    }
    unsigned int digit = (unsigned int)(*cursor - (unsigned char)'0');
    if (result > (MAX_SOURCE_COUNT - digit) / 10U) {
      fprintf(
          stderr,
          "projection-verify-runner: source count in %s exceeds %u\n",
          name,
          (unsigned int)MAX_SOURCE_COUNT);
      exit(1);
    }
    result = result * 10U + digit;
    ++cursor;
  }
  return result;
}

static char *duplicate_string(const char *value, const char *description) {
  size_t length = checked_string_length(value, description);
  if (length == SIZE_MAX) {
    die("string length overflow");
  }
  char *copy = malloc(length + 1U);
  if (copy == NULL) {
    die("out of memory while copying a string");
  }
  memcpy(copy, value, length + 1U);
  return copy;
}

static char *join_path(const char *left, const char *right) {
  size_t left_length = checked_string_length(left, "path");
  size_t right_length = checked_string_length(right, "path");
  int separator = left_length > 0U && left[left_length - 1U] != '/';
  size_t separator_length = separator ? 1U : 0U;
  if (left_length > SIZE_MAX - separator_length ||
      left_length + separator_length > SIZE_MAX - right_length ||
      left_length + separator_length + right_length == SIZE_MAX) {
    die("path length overflow");
  }
  size_t length = left_length + separator_length + right_length;
  char *result = malloc(length + 1U);
  if (result == NULL) {
    die("out of memory while constructing a path");
  }
  memcpy(result, left, left_length);
  size_t offset = left_length;
  if (separator) {
    result[offset++] = '/';
  }
  memcpy(result + offset, right, right_length);
  result[length] = '\0';
  return result;
}

static char *current_directory(void) {
  size_t capacity = 256U;
  for (;;) {
    char *buffer = malloc(capacity);
    if (buffer == NULL) {
      die("out of memory while resolving the action root");
    }
    if (getcwd(buffer, capacity) != NULL) {
      return buffer;
    }
    int saved_errno = errno;
    free(buffer);
    if (saved_errno != ERANGE || capacity > SIZE_MAX / 2U) {
      errno = saved_errno;
      die_errno("unable to resolve the action root");
    }
    capacity *= 2U;
  }
}

static char *resolve_path(const char *root, const char *path) {
  if (path[0] == '/') {
    return duplicate_string(path, "absolute path");
  }
  return join_path(root, path);
}

static int open_readonly(const char *path) {
  int descriptor;
  do {
    descriptor = open(path, O_RDONLY);
  } while (descriptor < 0 && errno == EINTR);
  if (descriptor < 0) {
    fprintf(
        stderr,
        "projection-verify-runner: unable to open '%s': %s\n",
        path,
        strerror(errno));
    exit(1);
  }
  return descriptor;
}

static int open_new_file(const char *path) {
  int descriptor;
  do {
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
  } while (descriptor < 0 && errno == EINTR);
  if (descriptor < 0) {
    fprintf(
        stderr,
        "projection-verify-runner: unable to create '%s': %s\n",
        path,
        strerror(errno));
    exit(1);
  }
  return descriptor;
}

static ssize_t read_retry(int descriptor, void *buffer, size_t length) {
  ssize_t result;
  do {
    result = read(descriptor, buffer, length);
  } while (result < 0 && errno == EINTR);
  return result;
}

static void write_all(int descriptor, const void *data, size_t length) {
  const unsigned char *bytes = data;
  size_t offset = 0;
  while (offset < length) {
    ssize_t result = write(descriptor, bytes + offset, length - offset);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      die_errno("unable to write output");
    }
    offset += (size_t)result;
  }
}

static void close_checked(int descriptor, const char *description) {
  if (close(descriptor) != 0) {
    fprintf(
        stderr,
        "projection-verify-runner: unable to close %s: %s\n",
        description,
        strerror(errno));
    exit(1);
  }
}

static struct stat stat_descriptor(int descriptor, const char *description) {
  struct stat status;
  int result;
  do {
    result = fstat(descriptor, &status);
  } while (result != 0 && errno == EINTR);
  if (result != 0) {
    fprintf(
        stderr,
        "projection-verify-runner: unable to stat %s: %s\n",
        description,
        strerror(errno));
    exit(1);
  }
  if (!S_ISREG(status.st_mode) || status.st_size < 0) {
    fprintf(
        stderr,
        "projection-verify-runner: %s is not a finite regular file\n",
        description);
    exit(1);
  }
  return status;
}

static uint64_t stat_size(const struct stat *status, const char *description) {
  (void)description;
  uintmax_t size = (uintmax_t)status->st_size;
#if UINTMAX_MAX > UINT64_MAX
  if (size > UINT64_MAX) {
    fprintf(
        stderr,
        "projection-verify-runner: %s is too large\n",
        description);
    exit(1);
  }
#endif
  return (uint64_t)size;
}

static void remove_if_exists(const char *path) {
  int result;
  do {
    result = unlink(path);
  } while (result != 0 && errno == EINTR);
  if (result != 0 && errno != ENOENT) {
    fprintf(
        stderr,
        "projection-verify-runner: unable to remove '%s': %s\n",
        path,
        strerror(errno));
    exit(1);
  }
}

static char *temporary_path(const char *output) {
  char suffix[64];
  int suffix_length = snprintf(
      suffix,
      sizeof(suffix),
      ".tmp.%ld",
      (long)getpid());
  if (suffix_length <= 0 || (size_t)suffix_length >= sizeof(suffix)) {
    die("temporary path suffix overflow");
  }
  size_t output_length = checked_string_length(output, "output path");
  size_t suffix_size = (size_t)suffix_length;
  if (output_length > SIZE_MAX - suffix_size ||
      output_length + suffix_size == SIZE_MAX) {
    die("temporary path length overflow");
  }
  char *path = malloc(output_length + suffix_size + 1U);
  if (path == NULL) {
    die("out of memory while constructing a temporary output path");
  }
  memcpy(path, output, output_length);
  memcpy(path + output_length, suffix, suffix_size + 1U);
  return path;
}

static void write_new_file(const char *path, const void *data, size_t length) {
  int descriptor = open_new_file(path);
  write_all(descriptor, data, length);
  close_checked(descriptor, path);
}

static void rename_checked(const char *source, const char *destination) {
  if (rename(source, destination) != 0) {
    fprintf(
        stderr,
        "projection-verify-runner: unable to publish '%s': %s\n",
        destination,
        strerror(errno));
    exit(1);
  }
}

static uint32_t rotate_right(uint32_t value, unsigned int count) {
  return (value >> count) | (value << (32U - count));
}

static uint32_t read_u32_be(const unsigned char *bytes) {
  return ((uint32_t)bytes[0] << 24U) |
         ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) |
         (uint32_t)bytes[3];
}

static void write_u32_be(unsigned char *bytes, uint32_t value) {
  bytes[0] = (unsigned char)(value >> 24U);
  bytes[1] = (unsigned char)(value >> 16U);
  bytes[2] = (unsigned char)(value >> 8U);
  bytes[3] = (unsigned char)value;
}

static void write_u64_be(unsigned char *bytes, uint64_t value) {
  for (size_t index = 0; index < 8U; ++index) {
    bytes[7U - index] = (unsigned char)(value >> (index * 8U));
  }
}

static void sha256_transform(
    struct sha256_context *context,
    const unsigned char block[SHA256_BLOCK_SIZE]) {
  static const uint32_t constants[64] = {
      UINT32_C(0x428a2f98), UINT32_C(0x71374491),
      UINT32_C(0xb5c0fbcf), UINT32_C(0xe9b5dba5),
      UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
      UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5),
      UINT32_C(0xd807aa98), UINT32_C(0x12835b01),
      UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
      UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe),
      UINT32_C(0x9bdc06a7), UINT32_C(0xc19bf174),
      UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
      UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc),
      UINT32_C(0x2de92c6f), UINT32_C(0x4a7484aa),
      UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
      UINT32_C(0x983e5152), UINT32_C(0xa831c66d),
      UINT32_C(0xb00327c8), UINT32_C(0xbf597fc7),
      UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
      UINT32_C(0x06ca6351), UINT32_C(0x14292967),
      UINT32_C(0x27b70a85), UINT32_C(0x2e1b2138),
      UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
      UINT32_C(0x650a7354), UINT32_C(0x766a0abb),
      UINT32_C(0x81c2c92e), UINT32_C(0x92722c85),
      UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
      UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3),
      UINT32_C(0xd192e819), UINT32_C(0xd6990624),
      UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
      UINT32_C(0x19a4c116), UINT32_C(0x1e376c08),
      UINT32_C(0x2748774c), UINT32_C(0x34b0bcb5),
      UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
      UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3),
      UINT32_C(0x748f82ee), UINT32_C(0x78a5636f),
      UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
      UINT32_C(0x90befffa), UINT32_C(0xa4506ceb),
      UINT32_C(0xbef9a3f7), UINT32_C(0xc67178f2),
  };
  uint32_t schedule[64];
  for (size_t index = 0; index < 16U; ++index) {
    schedule[index] = read_u32_be(block + index * 4U);
  }
  for (size_t index = 16U; index < 64U; ++index) {
    uint32_t value_15 = schedule[index - 15U];
    uint32_t value_2 = schedule[index - 2U];
    uint32_t sigma_0 =
        rotate_right(value_15, 7U) ^
        rotate_right(value_15, 18U) ^
        (value_15 >> 3U);
    uint32_t sigma_1 =
        rotate_right(value_2, 17U) ^
        rotate_right(value_2, 19U) ^
        (value_2 >> 10U);
    schedule[index] =
        schedule[index - 16U] + sigma_0 +
        schedule[index - 7U] + sigma_1;
  }

  uint32_t a = context->state[0];
  uint32_t b = context->state[1];
  uint32_t c = context->state[2];
  uint32_t d = context->state[3];
  uint32_t e = context->state[4];
  uint32_t f = context->state[5];
  uint32_t g = context->state[6];
  uint32_t h = context->state[7];
  for (size_t index = 0; index < 64U; ++index) {
    uint32_t sum_1 =
        rotate_right(e, 6U) ^
        rotate_right(e, 11U) ^
        rotate_right(e, 25U);
    uint32_t choice = (e & f) ^ ((~e) & g);
    uint32_t temporary_1 =
        h + sum_1 + choice + constants[index] + schedule[index];
    uint32_t sum_0 =
        rotate_right(a, 2U) ^
        rotate_right(a, 13U) ^
        rotate_right(a, 22U);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temporary_2 = sum_0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temporary_1;
    d = c;
    c = b;
    b = a;
    a = temporary_1 + temporary_2;
  }
  context->state[0] += a;
  context->state[1] += b;
  context->state[2] += c;
  context->state[3] += d;
  context->state[4] += e;
  context->state[5] += f;
  context->state[6] += g;
  context->state[7] += h;
}

static void sha256_initialize(struct sha256_context *context) {
  context->state[0] = UINT32_C(0x6a09e667);
  context->state[1] = UINT32_C(0xbb67ae85);
  context->state[2] = UINT32_C(0x3c6ef372);
  context->state[3] = UINT32_C(0xa54ff53a);
  context->state[4] = UINT32_C(0x510e527f);
  context->state[5] = UINT32_C(0x9b05688c);
  context->state[6] = UINT32_C(0x1f83d9ab);
  context->state[7] = UINT32_C(0x5be0cd19);
  context->total_bytes = 0;
  context->block_length = 0;
}

static void sha256_update(
    struct sha256_context *context,
    const void *data,
    size_t length) {
  if ((uintmax_t)length > SHA256_MAX_BYTES - context->total_bytes) {
    die("SHA-256 input length overflow");
  }
  context->total_bytes += (uint64_t)length;
  const unsigned char *bytes = data;
  size_t offset = 0;
  while (offset < length) {
    size_t available = SHA256_BLOCK_SIZE - context->block_length;
    size_t remaining = length - offset;
    size_t count = remaining < available ? remaining : available;
    memcpy(context->block + context->block_length, bytes + offset, count);
    context->block_length += count;
    offset += count;
    if (context->block_length == SHA256_BLOCK_SIZE) {
      sha256_transform(context, context->block);
      context->block_length = 0;
    }
  }
}

static void sha256_finalize(
    struct sha256_context *context,
    unsigned char digest[SHA256_DIGEST_SIZE]) {
  uint64_t bit_length = context->total_bytes * UINT64_C(8);
  context->block[context->block_length++] = 0x80U;
  if (context->block_length > 56U) {
    while (context->block_length < SHA256_BLOCK_SIZE) {
      context->block[context->block_length++] = 0;
    }
    sha256_transform(context, context->block);
    context->block_length = 0;
  }
  while (context->block_length < 56U) {
    context->block[context->block_length++] = 0;
  }
  write_u64_be(context->block + 56U, bit_length);
  sha256_transform(context, context->block);
  for (size_t index = 0; index < 8U; ++index) {
    write_u32_be(digest + index * 4U, context->state[index]);
  }
}

static void digest_hex(
    const unsigned char digest[SHA256_DIGEST_SIZE],
    char output[SHA256_DIGEST_SIZE * 2U + 1U]) {
  static const char digits[] = "0123456789abcdef";
  for (size_t index = 0; index < SHA256_DIGEST_SIZE; ++index) {
    output[index * 2U] = digits[digest[index] >> 4U];
    output[index * 2U + 1U] = digits[digest[index] & 0x0fU];
  }
  output[SHA256_DIGEST_SIZE * 2U] = '\0';
}

static void hash_file(
    const char *path,
    unsigned char digest[SHA256_DIGEST_SIZE],
    uint64_t *size_output) {
  int descriptor = open_readonly(path);
  struct stat status = stat_descriptor(descriptor, path);
  uint64_t expected_size = stat_size(&status, path);
  struct sha256_context context;
  sha256_initialize(&context);
  unsigned char buffer[IO_BUFFER_SIZE];
  uint64_t actual_size = 0;
  for (;;) {
    ssize_t count = read_retry(descriptor, buffer, sizeof(buffer));
    if (count < 0) {
      fprintf(
          stderr,
          "projection-verify-runner: unable to read '%s': %s\n",
          path,
          strerror(errno));
      exit(1);
    }
    if (count == 0) {
      break;
    }
    size_t length = (size_t)count;
    if (actual_size > UINT64_MAX - (uint64_t)length) {
      die("file size overflow while hashing");
    }
    actual_size += (uint64_t)length;
    sha256_update(&context, buffer, length);
  }
  close_checked(descriptor, path);
  if (actual_size != expected_size) {
    fprintf(
        stderr,
        "projection-verify-runner: '%s' changed size while being read\n",
        path);
    exit(1);
  }
  sha256_finalize(&context, digest);
  if (size_output != NULL) {
    *size_output = actual_size;
  }
}

static void initialize_compare_reader(struct compare_reader *reader, int fd) {
  reader->descriptor = fd;
  reader->position = 0;
  reader->length = 0;
  reader->eof = 0;
}

static void fill_compare_reader(struct compare_reader *reader) {
  if (reader->position < reader->length || reader->eof) {
    return;
  }
  ssize_t count = read_retry(
      reader->descriptor,
      reader->buffer,
      sizeof(reader->buffer));
  if (count < 0) {
    die_errno("unable to read a compared file");
  }
  reader->position = 0;
  reader->length = (size_t)count;
  reader->eof = count == 0;
}

static int first_file_difference(
    const char *left_path,
    const char *right_path,
    uint64_t *offset_output) {
  int left_descriptor = open_readonly(left_path);
  int right_descriptor = open_readonly(right_path);
  struct compare_reader left;
  struct compare_reader right;
  initialize_compare_reader(&left, left_descriptor);
  initialize_compare_reader(&right, right_descriptor);
  uint64_t offset = 0;
  int equal = 1;
  for (;;) {
    fill_compare_reader(&left);
    fill_compare_reader(&right);
    if (left.eof || right.eof) {
      if (!(left.eof && right.eof)) {
        equal = 0;
      }
      break;
    }
    size_t left_available = left.length - left.position;
    size_t right_available = right.length - right.position;
    size_t count =
        left_available < right_available ? left_available : right_available;
    if (memcmp(
            left.buffer + left.position,
            right.buffer + right.position,
            count) != 0) {
      size_t index = 0;
      while (index < count &&
             left.buffer[left.position + index] ==
                 right.buffer[right.position + index]) {
        ++index;
      }
      if (offset > UINT64_MAX - (uint64_t)index) {
        die("comparison offset overflow");
      }
      offset += (uint64_t)index;
      equal = 0;
      break;
    }
    left.position += count;
    right.position += count;
    if (offset > UINT64_MAX - (uint64_t)count) {
      die("comparison offset overflow");
    }
    offset += (uint64_t)count;
  }
  close_checked(left_descriptor, left_path);
  close_checked(right_descriptor, right_path);
  *offset_output = offset;
  return equal;
}

static void verify_equal_files(
    const char *description,
    const char *fresh_path,
    const char *committed_path,
    unsigned char fresh_digest[SHA256_DIGEST_SIZE]) {
  unsigned char committed_digest[SHA256_DIGEST_SIZE];
  uint64_t fresh_size;
  uint64_t committed_size;
  hash_file(fresh_path, fresh_digest, &fresh_size);
  hash_file(committed_path, committed_digest, &committed_size);
  uint64_t difference_offset;
  int equal = first_file_difference(
      fresh_path,
      committed_path,
      &difference_offset);
  if (equal &&
      (fresh_size != committed_size ||
       memcmp(fresh_digest, committed_digest, SHA256_DIGEST_SIZE) != 0)) {
    die("a compared file changed during verification");
  }
  if (!equal) {
    char fresh_hex[SHA256_DIGEST_SIZE * 2U + 1U];
    char committed_hex[SHA256_DIGEST_SIZE * 2U + 1U];
    digest_hex(fresh_digest, fresh_hex);
    digest_hex(committed_digest, committed_hex);
    fprintf(
        stderr,
        "projection-verify-runner: %s mismatch at byte offset %" PRIu64
        ": fresh_sha256=%s committed_sha256=%s fresh_size=%" PRIu64
        " committed_size=%" PRIu64 "\n",
        description,
        difference_offset,
        fresh_hex,
        committed_hex,
        fresh_size,
        committed_size);
    exit(1);
  }
}

static void sha256_update_u64(
    struct sha256_context *context,
    uint64_t value) {
  unsigned char encoded[8];
  write_u64_be(encoded, value);
  sha256_update(context, encoded, sizeof(encoded));
}

static void source_environment_name(
    char output[160],
    const char *category,
    size_t index,
    const char *suffix) {
  int length = snprintf(
      output,
      160U,
      "LEAN_PROJECTION_%s_SOURCE_%zu_%s",
      category,
      index,
      suffix);
  if (length <= 0 || (size_t)length >= 160U) {
    die("indexed source environment name overflow");
  }
}

static void hash_source_sequence(
    const char *action_root,
    const char *category,
    unsigned char digest[SHA256_DIGEST_SIZE]) {
  char count_name[96];
  int count_name_length = snprintf(
      count_name,
      sizeof(count_name),
      "LEAN_PROJECTION_%s_SOURCE_COUNT",
      category);
  if (count_name_length <= 0 ||
      (size_t)count_name_length >= sizeof(count_name)) {
    die("source count environment name overflow");
  }
  size_t count = parse_count(count_name);
  struct sha256_context context;
  sha256_initialize(&context);
  const char *previous_name = NULL;
  for (size_t index = 0; index < count; ++index) {
    char name_environment[160];
    char path_environment[160];
    source_environment_name(
        name_environment,
        category,
        index,
        "NAME");
    source_environment_name(
        path_environment,
        category,
        index,
        "PATH");
    const char *logical_name = required_environment(name_environment);
    const char *physical_value = required_environment(path_environment);
    if (previous_name != NULL && strcmp(previous_name, logical_name) >= 0) {
      fprintf(
          stderr,
          "projection-verify-runner: %s sources are not strictly sorted"
          " by logical name at index %zu\n",
          category,
          index);
      exit(1);
    }
    previous_name = logical_name;
    size_t logical_length =
        checked_string_length(logical_name, name_environment);
    sha256_update_u64(&context, (uint64_t)logical_length);
    sha256_update(&context, logical_name, logical_length);

    char *physical_path = resolve_path(action_root, physical_value);
    int descriptor = open_readonly(physical_path);
    struct stat status = stat_descriptor(descriptor, physical_path);
    uint64_t expected_size = stat_size(&status, physical_path);
    sha256_update_u64(&context, expected_size);
    unsigned char buffer[IO_BUFFER_SIZE];
    uint64_t actual_size = 0;
    for (;;) {
      ssize_t bytes_read = read_retry(descriptor, buffer, sizeof(buffer));
      if (bytes_read < 0) {
        fprintf(
            stderr,
            "projection-verify-runner: unable to read '%s': %s\n",
            physical_path,
            strerror(errno));
        exit(1);
      }
      if (bytes_read == 0) {
        break;
      }
      size_t length = (size_t)bytes_read;
      if (actual_size > UINT64_MAX - (uint64_t)length) {
        die("source file size overflow");
      }
      actual_size += (uint64_t)length;
      sha256_update(&context, buffer, length);
    }
    close_checked(descriptor, physical_path);
    if (actual_size != expected_size) {
      fprintf(
          stderr,
          "projection-verify-runner: source '%s' changed size while being read\n",
          physical_path);
      exit(1);
    }
    free(physical_path);
  }
  sha256_finalize(&context, digest);
}

static void buffer_reserve(struct byte_buffer *buffer, size_t additional) {
  if (buffer->length > SIZE_MAX - additional ||
      buffer->length + additional == SIZE_MAX) {
    die("metadata record size overflow");
  }
  size_t required = buffer->length + additional + 1U;
  if (required <= buffer->capacity) {
    return;
  }
  size_t capacity = buffer->capacity == 0U ? 256U : buffer->capacity;
  while (capacity < required) {
    if (capacity > SIZE_MAX / 2U) {
      capacity = required;
      break;
    }
    capacity *= 2U;
  }
  char *data = realloc(buffer->data, capacity);
  if (data == NULL) {
    die("out of memory while constructing metadata");
  }
  buffer->data = data;
  buffer->capacity = capacity;
}

static void buffer_append(
    struct byte_buffer *buffer,
    const void *data,
    size_t length) {
  buffer_reserve(buffer, length);
  memcpy(buffer->data + buffer->length, data, length);
  buffer->length += length;
  buffer->data[buffer->length] = '\0';
}

static void buffer_append_text(
    struct byte_buffer *buffer,
    const char *text) {
  buffer_append(buffer, text, strlen(text));
}

static void validate_utf8(const char *value, size_t length) {
  size_t index = 0;
  while (index < length) {
    unsigned char first = (unsigned char)value[index];
    if (first <= 0x7fU) {
      ++index;
      continue;
    }
    size_t continuation_count;
    unsigned char second_minimum = 0x80U;
    unsigned char second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      die("metadata string is not valid UTF-8");
    }
    if (continuation_count > length - index - 1U) {
      die("metadata string is not valid UTF-8");
    }
    unsigned char second = (unsigned char)value[index + 1U];
    if (second < second_minimum || second > second_maximum) {
      die("metadata string is not valid UTF-8");
    }
    for (size_t offset = 2U; offset <= continuation_count; ++offset) {
      unsigned char continuation =
          (unsigned char)value[index + offset];
      if (continuation < 0x80U || continuation > 0xbfU) {
        die("metadata string is not valid UTF-8");
      }
    }
    index += continuation_count + 1U;
  }
}

static void buffer_append_json_string(
    struct byte_buffer *buffer,
    const char *value,
    const char *description) {
  static const char hexadecimal[] = "0123456789abcdef";
  size_t length = checked_string_length(value, description);
  validate_utf8(value, length);
  buffer_append_text(buffer, "\"");
  for (size_t index = 0; index < length; ++index) {
    unsigned char byte = (unsigned char)value[index];
    switch (byte) {
      case '"':
        buffer_append_text(buffer, "\\\"");
        break;
      case '\\':
        buffer_append_text(buffer, "\\\\");
        break;
      case '\b':
        buffer_append_text(buffer, "\\b");
        break;
      case '\f':
        buffer_append_text(buffer, "\\f");
        break;
      case '\n':
        buffer_append_text(buffer, "\\n");
        break;
      case '\r':
        buffer_append_text(buffer, "\\r");
        break;
      case '\t':
        buffer_append_text(buffer, "\\t");
        break;
      default:
        if (byte < 0x20U) {
          char escaped[6] = {
              '\\',
              'u',
              '0',
              '0',
              hexadecimal[byte >> 4U],
              hexadecimal[byte & 0x0fU],
          };
          buffer_append(buffer, escaped, sizeof(escaped));
        } else {
          buffer_append(buffer, value + index, 1U);
        }
        break;
    }
  }
  buffer_append_text(buffer, "\"");
}

static void buffer_append_digest(
    struct byte_buffer *buffer,
    const unsigned char digest[SHA256_DIGEST_SIZE]) {
  char hexadecimal[SHA256_DIGEST_SIZE * 2U + 1U];
  digest_hex(digest, hexadecimal);
  buffer_append_text(buffer, "\"sha256:");
  buffer_append_text(buffer, hexadecimal);
  buffer_append_text(buffer, "\"");
}

static int first_memory_file_difference(
    const unsigned char *memory,
    size_t memory_length,
    const char *file_path,
    uint64_t *offset_output) {
  int descriptor = open_readonly(file_path);
  unsigned char buffer[IO_BUFFER_SIZE];
  size_t memory_offset = 0;
  uint64_t total_offset = 0;
  int equal = 1;
  for (;;) {
    ssize_t count = read_retry(descriptor, buffer, sizeof(buffer));
    if (count < 0) {
      die_errno("unable to read committed metadata lock");
    }
    if (count == 0) {
      if (memory_offset != memory_length) {
        equal = 0;
      }
      break;
    }
    size_t file_length = (size_t)count;
    size_t memory_remaining = memory_length - memory_offset;
    size_t compared =
        file_length < memory_remaining ? file_length : memory_remaining;
    if (memcmp(memory + memory_offset, buffer, compared) != 0) {
      size_t index = 0;
      while (index < compared &&
             memory[memory_offset + index] == buffer[index]) {
        ++index;
      }
      total_offset += (uint64_t)index;
      equal = 0;
      break;
    }
    memory_offset += compared;
    total_offset += (uint64_t)compared;
    if (file_length != compared) {
      equal = 0;
      break;
    }
  }
  close_checked(descriptor, file_path);
  *offset_output = total_offset;
  return equal;
}

static void verify_metadata_lock(
    const struct byte_buffer *record,
    const char *committed_lock) {
  struct sha256_context actual_context;
  unsigned char actual_digest[SHA256_DIGEST_SIZE];
  unsigned char committed_digest[SHA256_DIGEST_SIZE];
  sha256_initialize(&actual_context);
  sha256_update(&actual_context, record->data, record->length);
  sha256_finalize(&actual_context, actual_digest);
  uint64_t committed_size;
  hash_file(committed_lock, committed_digest, &committed_size);
  uint64_t difference_offset;
  int equal = first_memory_file_difference(
      (const unsigned char *)record->data,
      record->length,
      committed_lock,
      &difference_offset);
  if (equal &&
      ((uint64_t)record->length != committed_size ||
       memcmp(actual_digest, committed_digest, SHA256_DIGEST_SIZE) != 0)) {
    die("committed metadata lock changed during verification");
  }
  if (!equal) {
    char actual_hex[SHA256_DIGEST_SIZE * 2U + 1U];
    char committed_hex[SHA256_DIGEST_SIZE * 2U + 1U];
    digest_hex(actual_digest, actual_hex);
    digest_hex(committed_digest, committed_hex);
    fprintf(
        stderr,
        "projection-verify-runner: metadata lock mismatch at byte offset %"
        PRIu64 ": actual_sha256=%s committed_sha256=%s actual_size=%zu"
        " committed_size=%" PRIu64 "\n",
        difference_offset,
        actual_hex,
        committed_hex,
        record->length,
        committed_size);
    static const char heading[] =
        "projection-verify-runner: actual metadata record follows:\n";
    write_all(STDERR_FILENO, heading, sizeof(heading) - 1U);
    write_all(STDERR_FILENO, record->data, record->length);
    exit(1);
  }
}

static struct byte_buffer build_metadata_record(
    const char *platform,
    const char *toolchain_identity,
    const unsigned char exporter_source_revision[SHA256_DIGEST_SIZE],
    const unsigned char exporter_binary_digest[SHA256_DIGEST_SIZE],
    const unsigned char renderer_source_revision[SHA256_DIGEST_SIZE],
    const unsigned char renderer_binary_digest[SHA256_DIGEST_SIZE],
    const unsigned char manifest_digest[SHA256_DIGEST_SIZE],
    const unsigned char projection_digest[SHA256_DIGEST_SIZE]) {
  struct byte_buffer record = {0};
  buffer_append_text(&record, "{\n  \"schemaVersion\": \"1\",\n  \"platform\": ");
  buffer_append_json_string(&record, platform, "platform");
  buffer_append_text(&record, ",\n  \"toolchainIdentity\": ");
  buffer_append_json_string(
      &record,
      toolchain_identity,
      "toolchain identity");
  buffer_append_text(&record, ",\n  \"exporterSourceRevision\": ");
  buffer_append_digest(&record, exporter_source_revision);
  buffer_append_text(&record, ",\n  \"exporterBinarySha256\": ");
  buffer_append_digest(&record, exporter_binary_digest);
  buffer_append_text(&record, ",\n  \"rendererSourceRevision\": ");
  buffer_append_digest(&record, renderer_source_revision);
  buffer_append_text(&record, ",\n  \"rendererBinarySha256\": ");
  buffer_append_digest(&record, renderer_binary_digest);
  buffer_append_text(&record, ",\n  \"manifestSha256\": ");
  buffer_append_digest(&record, manifest_digest);
  buffer_append_text(&record, ",\n  \"projectionSha256\": ");
  buffer_append_digest(&record, projection_digest);
  buffer_append_text(&record, "\n}\n");
  return record;
}

int main(void) {
  if (atexit(cleanup_outputs) != 0) {
    die("unable to register output cleanup");
  }
  char *action_root = current_directory();
  const char *candidate_lock_value = getenv("LEAN_PROJECTION_CANDIDATE_LOCK");
  int candidate_mode = candidate_lock_value != NULL;
  if (candidate_mode) {
    if (candidate_lock_value[0] == '\0') {
      die("LEAN_PROJECTION_CANDIDATE_LOCK must not be empty");
    }
    (void)checked_string_length(
        candidate_lock_value,
        "LEAN_PROJECTION_CANDIDATE_LOCK");
  }
  const char *platform =
      required_environment("LEAN_PROJECTION_PLATFORM");
  const char *toolchain_identity =
      required_environment("LEAN_PROJECTION_TOOLCHAIN_IDENTITY");

  char *fresh_manifest = resolve_path(
      action_root,
      required_environment("LEAN_PROJECTION_FRESH_MANIFEST"));
  char *fresh_projection = resolve_path(
      action_root,
      required_environment("LEAN_PROJECTION_FRESH_PROJECTION"));
  char *committed_manifest = NULL;
  char *committed_projection = NULL;
  char *committed_lock = NULL;
  if (!candidate_mode) {
    committed_manifest = resolve_path(
        action_root,
        required_environment("LEAN_PROJECTION_COMMITTED_MANIFEST"));
    committed_projection = resolve_path(
        action_root,
        required_environment("LEAN_PROJECTION_COMMITTED_PROJECTION"));
    committed_lock = resolve_path(
        action_root,
        required_environment("LEAN_PROJECTION_COMMITTED_LOCK"));
  }
  char *exporter_binary = resolve_path(
      action_root,
      required_environment("LEAN_PROJECTION_EXPORTER_BINARY"));
  char *renderer_binary = resolve_path(
      action_root,
      required_environment("LEAN_PROJECTION_RENDERER_BINARY"));
  char *metadata_path = resolve_path(
      action_root,
      candidate_mode
          ? candidate_lock_value
          : required_environment("LEAN_PROJECTION_METADATA"));
  char *stamp_path = candidate_mode
      ? NULL
      : resolve_path(
            action_root,
            required_environment("LEAN_PROJECTION_STAMP"));

  if (!candidate_mode && strcmp(metadata_path, stamp_path) == 0) {
    die("metadata and stamp outputs must be distinct");
  }
  const char *fixed_inputs[7] = {
      fresh_manifest,
      fresh_projection,
      exporter_binary,
      renderer_binary,
  };
  size_t fixed_input_count = 4U;
  if (!candidate_mode) {
    fixed_inputs[fixed_input_count++] = committed_manifest;
    fixed_inputs[fixed_input_count++] = committed_projection;
    fixed_inputs[fixed_input_count++] = committed_lock;
  }
  for (size_t index = 0; index < fixed_input_count; ++index) {
    if (strcmp(metadata_path, fixed_inputs[index]) == 0 ||
        (!candidate_mode && strcmp(stamp_path, fixed_inputs[index]) == 0)) {
      die("an output path aliases a fixed input path");
    }
  }
  metadata_output = metadata_path;
  stamp_output = stamp_path;
  metadata_temporary = temporary_path(metadata_output);
  stamp_temporary = candidate_mode ? NULL : temporary_path(stamp_output);
  remove_if_exists(metadata_output);
  remove_if_exists(metadata_temporary);
  if (!candidate_mode) {
    remove_if_exists(stamp_output);
    remove_if_exists(stamp_temporary);
  }

  unsigned char manifest_digest[SHA256_DIGEST_SIZE];
  unsigned char projection_digest[SHA256_DIGEST_SIZE];
  if (candidate_mode) {
    hash_file(fresh_manifest, manifest_digest, NULL);
    hash_file(fresh_projection, projection_digest, NULL);
  } else {
    verify_equal_files(
        "manifest",
        fresh_manifest,
        committed_manifest,
        manifest_digest);
    verify_equal_files(
        "projection",
        fresh_projection,
        committed_projection,
        projection_digest);
  }

  unsigned char exporter_source_revision[SHA256_DIGEST_SIZE];
  unsigned char renderer_source_revision[SHA256_DIGEST_SIZE];
  unsigned char exporter_binary_digest[SHA256_DIGEST_SIZE];
  unsigned char renderer_binary_digest[SHA256_DIGEST_SIZE];
  hash_source_sequence(
      action_root,
      "EXPORTER",
      exporter_source_revision);
  hash_source_sequence(
      action_root,
      "RENDERER",
      renderer_source_revision);
  hash_file(exporter_binary, exporter_binary_digest, NULL);
  hash_file(renderer_binary, renderer_binary_digest, NULL);

  struct byte_buffer record = build_metadata_record(
      platform,
      toolchain_identity,
      exporter_source_revision,
      exporter_binary_digest,
      renderer_source_revision,
      renderer_binary_digest,
      manifest_digest,
      projection_digest);
  if (candidate_mode) {
    write_new_file(metadata_temporary, record.data, record.length);
    rename_checked(metadata_temporary, metadata_output);
  } else {
    verify_metadata_lock(&record, committed_lock);
    static const char stamp_content[] = "projection freshness verified\n";
    write_new_file(metadata_temporary, record.data, record.length);
    write_new_file(
        stamp_temporary,
        stamp_content,
        sizeof(stamp_content) - 1U);
    rename_checked(metadata_temporary, metadata_output);
    rename_checked(stamp_temporary, stamp_output);
  }
  outputs_committed = 1;

  free(record.data);
  free(action_root);
  free(fresh_manifest);
  free(committed_manifest);
  free(fresh_projection);
  free(committed_projection);
  free(committed_lock);
  free(exporter_binary);
  free(renderer_binary);
  free(metadata_output);
  free(stamp_output);
  free(metadata_temporary);
  free(stamp_temporary);
  metadata_output = NULL;
  stamp_output = NULL;
  metadata_temporary = NULL;
  stamp_temporary = NULL;
  return 0;
}
