#define _GNU_SOURCE

#include <cupsfilters/filter.h>
#include <ppd/ppd-filter.h>

#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUNDLE_MAGIC "SMT_PWG_BUNDLE_V1\n"
#define PPD_MARK "--SMT-PPD--\n"
#define OPTIONS_MARK "--SMT-OPTIONS--\n"
#define DOCUMENT_MARK "--SMT-DOCUMENT--\n"
#define MAX_PPD_BYTES (512 * 1024)
#define MAX_OPTIONS_BYTES 4096
#define MAX_DOCUMENT_BYTES (2 * 1024 * 1024)

static int JobCanceled = 0;

static void cancel_job(int sig) {
  (void)sig;
  JobCanceled = 1;
}

static const unsigned char *find_bytes(const unsigned char *haystack,
                                       size_t haystack_len,
                                       const char *needle) {
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || haystack_len < needle_len) {
    return NULL;
  }
  for (size_t i = 0; i <= haystack_len - needle_len; i++) {
    if (memcmp(haystack + i, needle, needle_len) == 0) {
      return haystack + i;
    }
  }
  return NULL;
}

static unsigned char *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  unsigned char *buf = NULL;
  long size;

  *out_len = 0;
  if (!fp) {
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
  }
  size = ftell(fp);
  if (size < 0) {
    fclose(fp);
    return NULL;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return NULL;
  }
  buf = (unsigned char *)malloc((size_t)size + 1);
  if (!buf) {
    fclose(fp);
    return NULL;
  }
  if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
    free(buf);
    fclose(fp);
    return NULL;
  }
  fclose(fp);
  buf[size] = 0;
  *out_len = (size_t)size;
  return buf;
}

static int write_file(const char *path, const unsigned char *data, size_t len) {
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  ssize_t written;
  size_t offset = 0;

  if (fd < 0) {
    return -1;
  }
  while (offset < len) {
    written = write(fd, data + offset, len - offset);
    if (written <= 0) {
      close(fd);
      return -1;
    }
    offset += (size_t)written;
  }
  close(fd);
  return 0;
}

static int copy_file(const char *src, const char *dst) {
  size_t len = 0;
  unsigned char *data = read_file(src, &len);
  int ok;

  if (!data) {
    return -1;
  }
  ok = write_file(dst, data, len);
  free(data);
  return ok;
}

static char *sanitize_options(const unsigned char *data, size_t len) {
  size_t out_len = len < MAX_OPTIONS_BYTES ? len : MAX_OPTIONS_BYTES;
  char *out = (char *)malloc(out_len + 1);
  if (!out) {
    return NULL;
  }
  for (size_t i = 0; i < out_len; i++) {
    unsigned char c = data[i];
    if (c == 0 || c == '\n' || c == '\r' || c == '\t') {
      out[i] = ' ';
    } else if (c < 32 || c > 126) {
      out[i] = '_';
    } else {
      out[i] = (char)c;
    }
  }
  out[out_len] = 0;
  return out;
}

static int parse_bundle(const unsigned char *data, size_t len,
                        const unsigned char **ppd, size_t *ppd_len,
                        const unsigned char **options, size_t *options_len,
                        const unsigned char **document,
                        size_t *document_len) {
  const unsigned char *ppd_mark;
  const unsigned char *options_mark;
  const unsigned char *document_mark;
  const unsigned char *ppd_start;
  const unsigned char *options_start;
  const unsigned char *document_start;

  *ppd = NULL;
  *ppd_len = 0;
  *options = NULL;
  *options_len = 0;
  *document = data;
  *document_len = len;

  if (len < strlen(BUNDLE_MAGIC) ||
      memcmp(data, BUNDLE_MAGIC, strlen(BUNDLE_MAGIC)) != 0) {
    return 0;
  }

  ppd_mark = find_bytes(data, len, PPD_MARK);
  if (!ppd_mark) {
    return 0;
  }
  options_mark = find_bytes(ppd_mark, len - (size_t)(ppd_mark - data),
                            OPTIONS_MARK);
  if (!options_mark) {
    return 0;
  }
  document_mark = find_bytes(options_mark,
                             len - (size_t)(options_mark - data),
                             DOCUMENT_MARK);
  if (!document_mark) {
    return 0;
  }

  ppd_start = ppd_mark + strlen(PPD_MARK);
  options_start = options_mark + strlen(OPTIONS_MARK);
  document_start = document_mark + strlen(DOCUMENT_MARK);

  *ppd = ppd_start;
  *ppd_len = (size_t)(options_mark - ppd_start);
  *options = options_start;
  *options_len = (size_t)(document_mark - options_start);
  *document = document_start;
  *document_len = len - (size_t)(document_start - data);

  if (*ppd_len > MAX_PPD_BYTES) {
    *ppd_len = MAX_PPD_BYTES;
  }
  if (*document_len > MAX_DOCUMENT_BYTES) {
    *document_len = MAX_DOCUMENT_BYTES;
  }
  return 1;
}

static void remove_temp_files(const char *dir) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/candidate.ppd", dir);
  unlink(path);
  snprintf(path, sizeof(path), "%s/document.pwg", dir);
  unlink(path);
  rmdir(dir);
}

int main(int argc, char **argv) {
  unsigned char *input = NULL;
  size_t input_len = 0;
  const unsigned char *ppd = NULL;
  const unsigned char *options = NULL;
  const unsigned char *document = NULL;
  size_t ppd_len = 0;
  size_t options_len = 0;
  size_t document_len = 0;
  char tmp_template[4096];
  char ppd_path[4096];
  char document_path[4096];
  char *tmpdir = NULL;
  char *job_options = NULL;
  const char *fallback_ppd;
  int devnull;
  int ret;
  char *filter_argv[8];
  cf_filter_out_format_t outformat = CF_FILTER_OUT_FORMAT_PDF;

  if (argc != 2) {
    return 0;
  }

  signal(SIGTERM, cancel_job);
  input = read_file(argv[1], &input_len);
  if (!input) {
    return 0;
  }

  parse_bundle(input, input_len, &ppd, &ppd_len, &options, &options_len,
               &document, &document_len);

  snprintf(tmp_template, sizeof(tmp_template), "%s/smt-pwg-bundle.XXXXXX",
           getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
  tmpdir = mkdtemp(tmp_template);
  if (!tmpdir) {
    free(input);
    return 0;
  }
  snprintf(ppd_path, sizeof(ppd_path), "%s/candidate.ppd", tmpdir);
  snprintf(document_path, sizeof(document_path), "%s/document.pwg", tmpdir);

  fallback_ppd = getenv("SMT_AFL_BUNDLE_FALLBACK_PPD");
  if (ppd && ppd_len > 0) {
    if (write_file(ppd_path, ppd, ppd_len) != 0) {
      remove_temp_files(tmpdir);
      free(input);
      return 0;
    }
  } else if (fallback_ppd && copy_file(fallback_ppd, ppd_path) == 0) {
    /* fallback PPD copied */
  } else {
    remove_temp_files(tmpdir);
    free(input);
    return 0;
  }

  if (!document || document_len == 0 ||
      write_file(document_path, document, document_len) != 0) {
    remove_temp_files(tmpdir);
    free(input);
    return 0;
  }

  if (options && options_len > 0) {
    job_options = sanitize_options(options, options_len);
  } else {
    job_options = strdup("PageSize=Letter ColorModel=Gray PrintQuality=Normal MediaType=Plain");
  }
  if (!job_options) {
    remove_temp_files(tmpdir);
    free(input);
    return 0;
  }

  setenv("PPD", ppd_path, 1);
  setenv("CONTENT_TYPE", "application/vnd.cups-pwg", 0);
  setenv("FINAL_CONTENT_TYPE", "application/pdf", 0);
  setenv("PRINTER", "parser-fuzzers", 0);
  setenv("DEVICE_URI", "file:/dev/null", 0);

  devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }

  filter_argv[0] = (char *)"pwgtopdf-bundle";
  filter_argv[1] = (char *)"1";
  filter_argv[2] = (char *)"afl";
  filter_argv[3] = (char *)"afl";
  filter_argv[4] = (char *)"1";
  filter_argv[5] = job_options;
  filter_argv[6] = document_path;
  filter_argv[7] = NULL;

  ret = ppdFilterCUPSWrapper(7, filter_argv, cfFilterPWGToPDF, &outformat,
                             &JobCanceled);
  (void)ret;

  free(job_options);
  remove_temp_files(tmpdir);
  free(input);
  return 0;
}
