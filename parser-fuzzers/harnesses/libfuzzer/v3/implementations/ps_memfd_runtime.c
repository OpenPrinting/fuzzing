// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CF_V3_PS_PPD_KEEPERS 16U

typedef struct cf_v3_ps_ppd_keeper_s
{
  int active;
  int fd;
  char path[32];
} cf_v3_ps_ppd_keeper_t;

static cf_v3_ps_ppd_keeper_t cf_v3_ps_ppd_keepers[CF_V3_PS_PPD_KEEPERS];

extern int __real_mkstemp(char *template_name);
extern FILE *__real_tmpfile(void);
extern int __real_unlink(const char *path);

static int
cf_v3_ps_track_ppd(int fd, const char *path)
{
  for (size_t index = 0U; index < CF_V3_PS_PPD_KEEPERS; index++)
    if (!cf_v3_ps_ppd_keepers[index].active)
    {
      cf_v3_ps_ppd_keepers[index].active = 1;
      cf_v3_ps_ppd_keepers[index].fd = fd;
      snprintf(cf_v3_ps_ppd_keepers[index].path,
               sizeof(cf_v3_ps_ppd_keepers[index].path), "%s", path);
      return 1;
    }
  return 0;
}

int
__wrap_mkstemp(char *template_name)
{
  size_t capacity;
  int keeper;
  int writer;
  char path[32];

  if (!template_name ||
      (!strstr(template_name, "cupsfilters-v2-input.") &&
       !strstr(template_name, "cupsfilters-v2-ppd.")))
    return __real_mkstemp(template_name);

  if (strstr(template_name, "cupsfilters-v2-input."))
  {
    int fd = memfd_create("cupsfilters-v3-ps-input", MFD_CLOEXEC);

    if (fd < 0)
      return __real_mkstemp(template_name);
    capacity = strlen(template_name) + 1U;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (strlen(path) + 1U <= capacity)
      memcpy(template_name, path, strlen(path) + 1U);
    return fd;
  }

  capacity = strlen(template_name) + 1U;
  keeper = memfd_create("cupsfilters-v3-ps-ppd", MFD_CLOEXEC);
  if (keeper < 0)
    return __real_mkstemp(template_name);
  writer = dup(keeper);
  if (writer < 0)
  {
    close(keeper);
    return __real_mkstemp(template_name);
  }
  snprintf(path, sizeof(path), "/proc/self/fd/%d", keeper);
  if (strlen(path) + 1U > capacity || !cf_v3_ps_track_ppd(keeper, path))
  {
    close(writer);
    close(keeper);
    return __real_mkstemp(template_name);
  }
  memcpy(template_name, path, strlen(path) + 1U);
  return writer;
}

FILE *
__wrap_tmpfile(void)
{
  int fd = memfd_create("cupsfilters-v3-ps-output", MFD_CLOEXEC);
  FILE *stream;

  if (fd < 0)
    return __real_tmpfile();
  stream = fdopen(fd, "w+b");
  if (!stream)
  {
    close(fd);
    return __real_tmpfile();
  }
  return stream;
}

int
__wrap_unlink(const char *path)
{
  if (path)
    for (size_t index = 0U; index < CF_V3_PS_PPD_KEEPERS; index++)
      if (cf_v3_ps_ppd_keepers[index].active &&
          !strcmp(path, cf_v3_ps_ppd_keepers[index].path))
      {
        int result = close(cf_v3_ps_ppd_keepers[index].fd);

        memset(&cf_v3_ps_ppd_keepers[index], 0,
               sizeof(cf_v3_ps_ppd_keepers[index]));
        return result;
      }
  return __real_unlink(path);
}

__attribute__((destructor)) static void
cf_v3_ps_release_ppd_keepers(void)
{
  for (size_t index = 0U; index < CF_V3_PS_PPD_KEEPERS; index++)
    if (cf_v3_ps_ppd_keepers[index].active)
      close(cf_v3_ps_ppd_keepers[index].fd);
}
