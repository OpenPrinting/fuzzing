#define _GNU_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACE_BYTES 32
#define TRACE_ASCII 48
#define DEFAULT_TRACE_LIMIT 256

static int trace_fd = -2;
static long trace_count = 0;
static long trace_limit = DEFAULT_TRACE_LIMIT;
static __thread int in_hook = 0;

static int (*real_memcmp_fn)(const void *, const void *, size_t) = NULL;
static int (*real_strcmp_fn)(const char *, const char *) = NULL;
static int (*real_strncmp_fn)(const char *, const char *, size_t) = NULL;
static int (*real_strcasecmp_fn)(const char *, const char *) = NULL;
static int (*real_strncasecmp_fn)(const char *, const char *, size_t) = NULL;

static int simple_memcmp(const void *a, const void *b, size_t n) {
  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;
  for (size_t i = 0; i < n; i++) {
    if (pa[i] != pb[i]) {
      return (int)pa[i] - (int)pb[i];
    }
  }
  return 0;
}

static int simple_strcmp(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return (unsigned char)*a - (unsigned char)*b;
}

static int simple_strncmp(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char ca = (unsigned char)a[i];
    unsigned char cb = (unsigned char)b[i];
    if (ca != cb || ca == 0 || cb == 0) {
      return (int)ca - (int)cb;
    }
  }
  return 0;
}

static int simple_strcasecmp(const char *a, const char *b) {
  while (*a && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
    a++;
    b++;
  }
  return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static int simple_strncasecmp(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char ca = (unsigned char)tolower((unsigned char)a[i]);
    unsigned char cb = (unsigned char)tolower((unsigned char)b[i]);
    if (ca != cb || ca == 0 || cb == 0) {
      return (int)ca - (int)cb;
    }
  }
  return 0;
}

static size_t bounded_strlen(const char *s, size_t limit) {
  size_t n = 0;
  if (!s) {
    return 0;
  }
  while (n < limit && s[n] != 0) {
    n++;
  }
  return n;
}

static void ensure_real_functions(void) {
  if (real_memcmp_fn && real_strcmp_fn && real_strncmp_fn &&
      real_strcasecmp_fn && real_strncasecmp_fn) {
    return;
  }
  if (in_hook) {
    return;
  }
  in_hook = 1;
  real_memcmp_fn = (int (*)(const void *, const void *, size_t))dlsym(RTLD_NEXT, "memcmp");
  real_strcmp_fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "strcmp");
  real_strncmp_fn = (int (*)(const char *, const char *, size_t))dlsym(RTLD_NEXT, "strncmp");
  real_strcasecmp_fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "strcasecmp");
  real_strncasecmp_fn = (int (*)(const char *, const char *, size_t))dlsym(RTLD_NEXT, "strncasecmp");
  in_hook = 0;
}

static void ensure_trace_fd(void) {
  const char *path;
  const char *limit;
  if (trace_fd != -2 || in_hook) {
    return;
  }
  in_hook = 1;
  path = getenv("SMT_FUZZER_COMPARE_TRACE");
  limit = getenv("SMT_FUZZER_COMPARE_TRACE_LIMIT");
  if (limit && *limit) {
    char *end = NULL;
    long parsed = strtol(limit, &end, 10);
    if (end && *end == 0 && parsed >= 0) {
      trace_limit = parsed;
    }
  }
  if (!path || !*path || trace_limit == 0) {
    trace_fd = -1;
    in_hook = 0;
    return;
  }
  trace_fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0600);
  if (trace_fd >= 0) {
    const char *header = "pid\tpc\top\tret\tlen\ta_hex\tb_hex\ta_ascii\tb_ascii\n";
    ssize_t ignored = write(trace_fd, header, strlen(header));
    (void)ignored;
  }
  in_hook = 0;
}

static void encode_hex(char *out, size_t out_len, const unsigned char *data, size_t len) {
  static const char hexdigits[] = "0123456789abcdef";
  size_t n = len < TRACE_BYTES ? len : TRACE_BYTES;
  size_t offset = 0;
  if (out_len == 0) {
    return;
  }
  for (size_t i = 0; i < n && offset + 2 < out_len; i++) {
    out[offset++] = hexdigits[data[i] >> 4];
    out[offset++] = hexdigits[data[i] & 15];
  }
  out[offset] = 0;
}

static void encode_ascii(char *out, size_t out_len, const unsigned char *data, size_t len) {
  size_t n = len < TRACE_ASCII ? len : TRACE_ASCII;
  size_t offset = 0;
  if (out_len == 0) {
    return;
  }
  for (size_t i = 0; i < n && offset + 1 < out_len; i++) {
    unsigned char c = data[i];
    if (c == '\t' || c == '\n' || c == '\r') {
      out[offset++] = ' ';
    } else if (c >= 32 && c <= 126) {
      out[offset++] = (char)c;
    } else {
      out[offset++] = '.';
    }
  }
  out[offset] = 0;
}

static void trace_compare(const char *op, int ret, size_t len, const void *a,
                          const void *b, void *pc) {
  char a_hex[(TRACE_BYTES * 2) + 1];
  char b_hex[(TRACE_BYTES * 2) + 1];
  char a_ascii[TRACE_ASCII + 1];
  char b_ascii[TRACE_ASCII + 1];
  char line[512];
  int written;

  if (in_hook) {
    return;
  }
  ensure_trace_fd();
  if (trace_fd < 0 || trace_count >= trace_limit) {
    return;
  }

  in_hook = 1;
  encode_hex(a_hex, sizeof(a_hex), (const unsigned char *)a, len);
  encode_hex(b_hex, sizeof(b_hex), (const unsigned char *)b, len);
  encode_ascii(a_ascii, sizeof(a_ascii), (const unsigned char *)a, len);
  encode_ascii(b_ascii, sizeof(b_ascii), (const unsigned char *)b, len);
  written = snprintf(line, sizeof(line), "%ld\t%p\t%s\t%d\t%zu\t%s\t%s\t%s\t%s\n",
                     (long)getpid(), pc, op, ret, len, a_hex, b_hex, a_ascii, b_ascii);
  if (written > 0) {
    if ((size_t)written > sizeof(line)) {
      written = (int)sizeof(line);
    }
    ssize_t ignored = write(trace_fd, line, (size_t)written);
    (void)ignored;
    trace_count++;
  }
  in_hook = 0;
}

int memcmp(const void *a, const void *b, size_t n) {
  int ret;
  ensure_real_functions();
  ret = real_memcmp_fn ? real_memcmp_fn(a, b, n) : simple_memcmp(a, b, n);
  trace_compare("memcmp", ret, n, a, b, __builtin_return_address(0));
  return ret;
}

int strcmp(const char *a, const char *b) {
  size_t n;
  int ret;
  ensure_real_functions();
  ret = real_strcmp_fn ? real_strcmp_fn(a, b) : simple_strcmp(a, b);
  n = bounded_strlen(a, TRACE_ASCII);
  if (bounded_strlen(b, TRACE_ASCII) > n) {
    n = bounded_strlen(b, TRACE_ASCII);
  }
  trace_compare("strcmp", ret, n + 1, a, b, __builtin_return_address(0));
  return ret;
}

int strncmp(const char *a, const char *b, size_t n) {
  int ret;
  ensure_real_functions();
  ret = real_strncmp_fn ? real_strncmp_fn(a, b, n) : simple_strncmp(a, b, n);
  trace_compare("strncmp", ret, n, a, b, __builtin_return_address(0));
  return ret;
}

int strcasecmp(const char *a, const char *b) {
  size_t n;
  int ret;
  ensure_real_functions();
  ret = real_strcasecmp_fn ? real_strcasecmp_fn(a, b) : simple_strcasecmp(a, b);
  n = bounded_strlen(a, TRACE_ASCII);
  if (bounded_strlen(b, TRACE_ASCII) > n) {
    n = bounded_strlen(b, TRACE_ASCII);
  }
  trace_compare("strcasecmp", ret, n + 1, a, b, __builtin_return_address(0));
  return ret;
}

int strncasecmp(const char *a, const char *b, size_t n) {
  int ret;
  ensure_real_functions();
  ret = real_strncasecmp_fn ? real_strncasecmp_fn(a, b, n) : simple_strncasecmp(a, b, n);
  trace_compare("strncasecmp", ret, n, a, b, __builtin_return_address(0));
  return ret;
}
