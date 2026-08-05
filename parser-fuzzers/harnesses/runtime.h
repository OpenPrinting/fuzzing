#ifndef CUPSFILTERS_FUZZ_RUNTIME_H
#define CUPSFILTERS_FUZZ_RUNTIME_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char cf_fuzz_data_directory[PATH_MAX];

static inline void cf_fuzz_init_runtime(void) {
  char executable[PATH_MAX];
  char fontconfig_file[PATH_MAX];
  char *slash;
  ssize_t length;

  if (cf_fuzz_data_directory[0]) {
    return;
  }
  length = readlink("/proc/self/exe", executable, sizeof(executable) - 1U);
  if (length <= 0 || (size_t)length >= sizeof(executable) - 1U) {
    snprintf(cf_fuzz_data_directory, sizeof(cf_fuzz_data_directory), ".");
    return;
  }
  executable[length] = '\0';
  slash = strrchr(executable, '/');
  if (!slash) {
    snprintf(cf_fuzz_data_directory, sizeof(cf_fuzz_data_directory), ".");
    return;
  }
  *slash = '\0';
  snprintf(cf_fuzz_data_directory, sizeof(cf_fuzz_data_directory),
           "%s/cups-data", executable);
  snprintf(fontconfig_file, sizeof(fontconfig_file), "%s/fonts.conf",
           executable);
  (void)setenv("FONTCONFIG_FILE", fontconfig_file, 1);
}

static inline const char *cf_fuzz_data_dir(void) {
  cf_fuzz_init_runtime();
  return cf_fuzz_data_directory;
}

static inline int cf_fuzz_write_all(int fd, const uint8_t *data, size_t size) {
  size_t offset = 0;

  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);
    if (written <= 0) {
      return -1;
    }
    offset += (size_t)written;
  }
  return 0;
}

#endif
