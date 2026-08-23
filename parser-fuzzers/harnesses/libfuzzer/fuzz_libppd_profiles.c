// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <cupsfilters/driver.h>
#include <ppd/ppd.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef LIBPPD_PROFILES_MAX_INPUT
#define LIBPPD_PROFILES_MAX_INPUT (256U * 1024U)
#endif

#define LIBPPD_PROFILES_MAX_ATTRS 4096
#define LIBPPD_PROFILES_PIXELS 16

#ifdef LIBPPD_PROFILES_DISABLE_LSAN
int __lsan_is_turned_off(void) {
  return 1;
}
#endif

typedef struct {
  const char *color_model;
  const char *media;
  const char *resolution;
  const char *ink;
} libppd_profile_selector_t;

static int libppd_profiles_write_all(int fd, const uint8_t *data,
                                     size_t size) {
  size_t offset = 0;

  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);

    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return -1;
    }
    offset += (size_t)written;
  }

  return 0;
}

static int libppd_profiles_make_temp(char *path, size_t path_size) {
  const char *tmpdir = getenv("TMPDIR");
  int length;

  if (!tmpdir || !tmpdir[0]) {
    tmpdir = "/tmp";
  }

  length = snprintf(path, path_size, "%s/libppd-profiles.XXXXXX", tmpdir);
  if (length < 0 || (size_t)length >= path_size) {
    return -1;
  }

  return mkstemp(path);
}

typedef struct {
  char last_message[1024];
  unsigned int messages;
} libppd_profile_log_t;

static void libppd_profiles_log(void *data, cf_loglevel_t level,
                                const char *message, ...) {
  libppd_profile_log_t *state = (libppd_profile_log_t *)data;
  va_list args;

  (void)level;
  if (!state || !message) {
    return;
  }

  va_start(args, message);
  (void)vsnprintf(state->last_message, sizeof(state->last_message), message,
                  args);
  va_end(args);
  state->messages++;
}

#ifdef LIBPPD_PROFILES_DEEP_MODE
static int libppd_profiles_parse_pair(const char *value, float *first,
                                      float *second) {
  return value && sscanf(value, "%f%f", first, second) == 2 &&
         isfinite(*first) && isfinite(*second);
}

static int libppd_profiles_unit_pair_is_safe(const char *value) {
  float first;
  float second;

  return libppd_profiles_parse_pair(value, &first, &second) &&
         first >= 0.0f && first <= 1.0f && second >= 0.0f &&
         second <= 1.0f;
}

static int libppd_profiles_gamma_is_safe(const char *value) {
  float gamma;
  float density;

  return libppd_profiles_parse_pair(value, &gamma, &density) &&
         gamma > 0.0f && gamma <= 16.0f && density > 0.0f &&
         density <= 1.0f;
}

static int libppd_profiles_dither_is_safe(const char *value) {
  float values[3];
  const float minimum_last_value =
      ((float)CF_MAX_LUT * (float)CF_MAX_LUT) / (float)INT_MAX;
  int count;
  int index;

  if (!value) {
    return 0;
  }

  values[0] = values[1] = values[2] = 0.0f;
  count = sscanf(value, "%f%f%f", values, values + 1, values + 2);
  if (count < 1) {
    return 0;
  }

  for (index = 0; index < count; index++) {
    if (!isfinite(values[index]) || values[index] < 0.0f ||
        values[index] > 4096.0f) {
      return 0;
    }
  }

  /*
   * cfLutNew computes maxval = CF_MAX_LUT / last and then multiplies
   * maxval by every LUT index in int arithmetic. Keep that product in range
   * while leaving the rest of the legal dither shape available to fuzzing.
   */
  return values[count - 1] >= minimum_last_value;
}

static int libppd_profiles_rgb_sample_is_safe(const char *value) {
  float values[7];
  int count;
  int index;

  if (!value) {
    return 0;
  }

  count = sscanf(value, "%f%f%f%f%f%f%f", values, values + 1, values + 2,
                 values + 3, values + 4, values + 5, values + 6);
  if (count < 4) {
    return 0;
  }

  for (index = 0; index < count; index++) {
    if (!isfinite(values[index]) || values[index] < 0.0f ||
        values[index] > 1.0f) {
      return 0;
    }
  }

  return 1;
}

static int libppd_profiles_attributes_are_safe(const ppd_file_t *ppd) {
  int index;

  if (!ppd || ppd->num_attrs < 0 ||
      ppd->num_attrs > LIBPPD_PROFILES_MAX_ATTRS) {
    return 0;
  }

  for (index = 0; index < ppd->num_attrs; index++) {
    const ppd_attr_t *attr = ppd->attrs[index];
    float value;

    if (!attr || !attr->value) {
      return 0;
    }

    if (!strcasecmp(attr->name, "cupsRGBSample")) {
      if (!libppd_profiles_rgb_sample_is_safe(attr->value)) {
        return 0;
      }
    } else if (strcasestr(attr->name, "Dither")) {
      if (!libppd_profiles_dither_is_safe(attr->value)) {
        return 0;
      }
    } else if (strlen(attr->name) >= 2 &&
               !strcasecmp(attr->name + strlen(attr->name) - 2, "XY")) {
      int previous;
      int matching_points = 1;

      if (!libppd_profiles_unit_pair_is_safe(attr->value)) {
        return 0;
      }
      for (previous = 0; previous < index; previous++) {
        const ppd_attr_t *candidate = ppd->attrs[previous];
        int same_spec;

        if (!candidate || strcasecmp(candidate->name, attr->name)) {
          continue;
        }
        same_spec = !strcasecmp(candidate->spec, attr->spec);
        if (same_spec && ++matching_points > 98) {
          /*
           * cfCMYKSetCurve logs four floats after advancing past all points.
           * Keep the real logger enabled while isolating the known 99/100
           * point stack read from long-running exploration.
           */
          return 0;
        }
      }
    } else if (strcasestr(attr->name, "Gamma")) {
      if (!libppd_profiles_gamma_is_safe(attr->value)) {
        return 0;
      }
    } else if (!strcasecmp(attr->name, "cupsBlackGeneration") ||
               strcasestr(attr->name, "LtDk")) {
      if (!libppd_profiles_unit_pair_is_safe(attr->value)) {
        return 0;
      }
    } else if (!strcasecmp(attr->name, "cupsInkLimit")) {
      if (sscanf(attr->value, "%f", &value) != 1 || !isfinite(value) ||
          value < 0.0f || value > 7.0f) {
        return 0;
      }
    }
  }

  return 1;
}
#endif

static void libppd_profiles_exercise_rgb(cf_rgb_t *rgb,
                                         const uint8_t *data, size_t size) {
  static const unsigned char rgb_patterns[12][3] = {
      {0, 0, 0},       {0, 0, 0},       {255, 255, 255}, {255, 255, 255},
      {255, 0, 0},     {255, 0, 0},     {0, 255, 0},     {0, 255, 0},
      {0, 0, 255},     {0, 0, 255},     {127, 127, 127}, {127, 127, 127},
  };
  static const unsigned char gray_patterns[12] = {
      0, 0, 255, 255, 1, 1, 254, 254, 63, 63, 127, 127,
  };
  unsigned char gray[LIBPPD_PROFILES_PIXELS];
  unsigned char pixels[LIBPPD_PROFILES_PIXELS * 3];
  unsigned char output[LIBPPD_PROFILES_PIXELS * CF_MAX_RGB];
  size_t index;

  if (!rgb) {
    return;
  }

  memcpy(pixels, rgb_patterns, sizeof(rgb_patterns));
  memcpy(gray, gray_patterns, sizeof(gray_patterns));
  for (index = sizeof(rgb_patterns); index < sizeof(pixels); index++) {
    size_t offset =
        size > 1 ? index * (size - 1) / (sizeof(pixels) - 1) : 0;
    pixels[index] = size ? data[offset] : (unsigned char)(index * 29U);
  }
  for (index = sizeof(gray_patterns); index < sizeof(gray); index++) {
    size_t offset = size > 1 ? index * (size - 1) / (sizeof(gray) - 1) : 0;
    gray[index] = size ? data[offset] : (unsigned char)(index * 31U);
  }

  cfRGBDoGray(rgb, gray, output, LIBPPD_PROFILES_PIXELS);
  cfRGBDoRGB(rgb, pixels, output, LIBPPD_PROFILES_PIXELS);
}

static void libppd_profiles_exercise_cmyk(cf_cmyk_t *cmyk,
                                          const uint8_t *data, size_t size) {
  static const unsigned char patterns[12][4] = {
      {0, 0, 0, 0},       {255, 255, 255, 255}, {1, 1, 1, 1},
      {254, 254, 254, 254}, {255, 0, 0, 0},       {0, 255, 0, 0},
      {0, 0, 255, 0},     {0, 0, 0, 255},       {255, 255, 0, 0},
      {0, 255, 255, 0},   {255, 0, 255, 0},     {127, 128, 64, 192},
  };
  unsigned char input[LIBPPD_PROFILES_PIXELS * 4];
  short output[LIBPPD_PROFILES_PIXELS * CF_MAX_CHAN];
  size_t index;

  if (!cmyk) {
    return;
  }

  memcpy(input, patterns, sizeof(patterns));
  for (index = sizeof(patterns); index < sizeof(input); index++) {
    size_t offset =
        size > 1 ? index * (size - 1) / (sizeof(input) - 1) : 0;
    input[index] = size ? data[offset] : (unsigned char)(index * 37U);
  }

  cfCMYKDoBlack(cmyk, input, output, LIBPPD_PROFILES_PIXELS);
  cfCMYKDoGray(cmyk, input, output, LIBPPD_PROFILES_PIXELS);
  cfCMYKDoRGB(cmyk, input, output, LIBPPD_PROFILES_PIXELS);
  cfCMYKDoCMYK(cmyk, input, output, LIBPPD_PROFILES_PIXELS);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const libppd_profile_selector_t selectors[] = {
      {"Black", "Plain", "300dpi", "Black"},
      {"Gray", "Plain", "600dpi", "LightBlack"},
      {"RGB", "Glossy", "600dpi", "Cyan"},
      {"CMYK", "Plain", "300dpi", "Magenta"},
      {"CMYK", "Plain", "300x600dpi", "Yellow"},
  };
  char path[1024];
  libppd_profile_log_t log_state;
  ppd_file_t *ppd;
  size_t index;
  int fd;

  if (size > LIBPPD_PROFILES_MAX_INPUT) {
    return 0;
  }

  fd = libppd_profiles_make_temp(path, sizeof(path));
  if (fd < 0) {
    return 0;
  }
  if (libppd_profiles_write_all(fd, data, size) != 0) {
    close(fd);
    unlink(path);
    return 0;
  }
  if (close(fd) != 0) {
    unlink(path);
    return 0;
  }

  ppd = ppdOpenFile(path);
  unlink(path);
  if (!ppd) {
    return 0;
  }

  if (ppd->num_attrs < 0 || ppd->num_attrs > LIBPPD_PROFILES_MAX_ATTRS) {
    ppdClose(ppd);
    return 0;
  }

#ifdef LIBPPD_PROFILES_DEEP_MODE
  if (!libppd_profiles_attributes_are_safe(ppd)) {
    ppdClose(ppd);
    return 0;
  }
#endif

  memset(&log_state, 0, sizeof(log_state));
  for (index = 0; index < sizeof(selectors) / sizeof(selectors[0]); index++) {
    const libppd_profile_selector_t *selector = selectors + index;
    cf_cmyk_t *cmyk;
    cf_lut_t *lut;
    cf_rgb_t *rgb;
    cf_logfunc_t log = libppd_profiles_log;
    void *log_data = &log_state;

    rgb = ppdRGBLoad(ppd, selector->color_model, selector->media,
                     selector->resolution, log, log_data);
    libppd_profiles_exercise_rgb(rgb, data, size);
    cfRGBDelete(rgb);

    cmyk = ppdCMYKLoad(ppd, selector->color_model, selector->media,
                       selector->resolution, log, log_data);
    libppd_profiles_exercise_cmyk(cmyk, data, size);
    cfCMYKDelete(cmyk);

    lut = ppdLutLoad(ppd, selector->color_model, selector->media,
                     selector->resolution, selector->ink, log, log_data);
    cfLutDelete(lut);
  }

  ppdClose(ppd);
  return 0;
}
