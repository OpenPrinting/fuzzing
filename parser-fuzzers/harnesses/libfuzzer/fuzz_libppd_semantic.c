// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <cups/ipp.h>
#include <cups/raster.h>
#include <ppd/ppd.h>

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef LIBPPD_SEMANTIC_MAX_INPUT
#define LIBPPD_SEMANTIC_MAX_INPUT (1024U * 1024U)
#endif

#define LIBPPD_SEMANTIC_MAX_ATTRS 4096
#define LIBPPD_SEMANTIC_MAX_OPTIONS 512
#define LIBPPD_SEMANTIC_MAX_CHOICES 8192
#define LIBPPD_SEMANTIC_MAX_CUSTOM_PARAMS 1024
#define LIBPPD_SEMANTIC_REGULAR_MARKS 8
#define LIBPPD_SEMANTIC_CUSTOM_MARKS 4
#define LIBPPD_SEMANTIC_CUSTOM_PARAMS_PER_MARK 8
#define LIBPPD_SEMANTIC_MARK_VALUE_SIZE 2048
#define LIBPPD_SEMANTIC_STATE_OPTIONS 8
#define LIBPPD_SEMANTIC_MAX_RESOLUTION 16384U

#ifdef LIBPPD_SEMANTIC_DISABLE_LSAN
/* Duplicate PPD singleton/custom keys overwrite allocations owned by libppd. */
int __lsan_is_turned_off(void) {
  return 1;
}
#endif

typedef struct {
  char keyword[PPD_MAX_NAME];
  char value[LIBPPD_SEMANTIC_MARK_VALUE_SIZE];
} libppd_mark_action_t;

static int libppd_write_all(int fd, const uint8_t *data, size_t size) {
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

static int libppd_make_temp_ppd(char *path, size_t path_size) {
  const char *tmpdir = getenv("TMPDIR");
  int length;

  if (!tmpdir || !tmpdir[0]) {
    tmpdir = "/tmp";
  }

  length = snprintf(path, path_size, "%s/libppd-semantic.XXXXXX", tmpdir);
  if (length < 0 || (size_t)length >= path_size) {
    return -1;
  }

  return mkstemp(path);
}

static uint64_t libppd_hash(const uint8_t *data, size_t size) {
  uint64_t hash = UINT64_C(1469598103934665603);
  size_t index;

  for (index = 0; index < size; index++) {
    hash ^= data[index];
    hash *= UINT64_C(1099511628211);
  }

  return hash;
}

static int libppd_within_work_budget(ppd_file_t *ppd) {
  ppd_option_t *option;
  size_t options = 0;
  size_t choices = 0;
  size_t custom_params = 0;

  if (!ppd || ppd->num_attrs < 0 ||
      ppd->num_attrs > LIBPPD_SEMANTIC_MAX_ATTRS ||
      ppd->num_sizes < 0 || ppd->num_sizes > LIBPPD_SEMANTIC_MAX_CHOICES ||
      ppd->num_consts < 0 ||
      ppd->num_consts > LIBPPD_SEMANTIC_MAX_CHOICES ||
      ppd->num_filters < 0 ||
      ppd->num_filters > LIBPPD_SEMANTIC_MAX_OPTIONS) {
    return 0;
  }

  for (option = ppdFirstOption(ppd); option; option = ppdNextOption(ppd)) {
    ppd_coption_t *custom;
    ppd_cparam_t *param;

    if (++options > LIBPPD_SEMANTIC_MAX_OPTIONS ||
        option->num_choices < 0 ||
        (size_t)option->num_choices >
            LIBPPD_SEMANTIC_MAX_CHOICES - choices) {
      return 0;
    }
    choices += (size_t)option->num_choices;

    custom = ppdFindCustomOption(ppd, option->keyword);
    if (!custom) {
      continue;
    }

    for (param = ppdFirstCustomParam(custom); param;
         param = ppdNextCustomParam(custom)) {
      if (++custom_params > LIBPPD_SEMANTIC_MAX_CUSTOM_PARAMS) {
        return 0;
      }
    }
  }

  return 1;
}

static int libppd_append(char *buffer, size_t buffer_size, size_t *used,
                         const char *format, ...) {
  va_list args;
  int length;

  if (*used >= buffer_size) {
    return 0;
  }

  va_start(args, format);
  length = vsnprintf(buffer + *used, buffer_size - *used, format, args);
  va_end(args);
  if (length < 0 || (size_t)length >= buffer_size - *used) {
    return 0;
  }

  *used += (size_t)length;
  return 1;
}

static int libppd_append_custom_value(char *buffer, size_t buffer_size,
                                      size_t *used,
                                      const ppd_cparam_t *param) {
  switch (param->type) {
    case PPD_CUSTOM_CURVE:
      return libppd_append(buffer, buffer_size, used, "%.9g",
                           (double)param->maximum.custom_curve);
    case PPD_CUSTOM_INT:
      return libppd_append(buffer, buffer_size, used, "%d",
                           param->maximum.custom_int);
    case PPD_CUSTOM_INVCURVE:
      return libppd_append(buffer, buffer_size, used, "%.9g",
                           (double)param->maximum.custom_invcurve);
    case PPD_CUSTOM_POINTS:
      return libppd_append(buffer, buffer_size, used, "%.9g",
                           (double)param->maximum.custom_points);
    case PPD_CUSTOM_REAL:
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
    {
      float value = param->maximum.custom_real;

      if (value > 1000000.0f) {
        value = 1000000.0f;
      } else if (value < -1000000.0f) {
        value = -1000000.0f;
      }
      return libppd_append(buffer, buffer_size, used, "%.9g", (double)value);
    }
#else
      return libppd_append(buffer, buffer_size, used, "%.9g",
                           (double)param->maximum.custom_real);
#endif
    case PPD_CUSTOM_PASSCODE:
      return libppd_append(buffer, buffer_size, used, "1");
    case PPD_CUSTOM_PASSWORD:
    case PPD_CUSTOM_STRING:
      return libppd_append(buffer, buffer_size, used, "A");
    case PPD_CUSTOM_UNKNOWN:
      return 0;
  }

  return 0;
}

#ifdef LIBPPD_SEMANTIC_DEEP_MODE
static int libppd_deep_custom_page_is_safe(ppd_file_t *ppd) {
  ppd_coption_t *custom = ppdFindCustomOption(ppd, "PageSize");
  ppd_cparam_t *height;
  ppd_cparam_t *width;

  if (!custom) {
    return 1;
  }

  width = ppdFindCustomParam(custom, "Width");
  height = ppdFindCustomParam(custom, "Height");
  return (!width || width->type == PPD_CUSTOM_POINTS) &&
         (!height || height->type == PPD_CUSTOM_POINTS);
}

static int libppd_deep_resolution_text_is_safe(const char *text) {
  const unsigned char *cursor = (const unsigned char *)text;

  while (*cursor) {
    unsigned int value = 0;

    if (!isdigit(*cursor)) {
      cursor++;
      continue;
    }

    do {
      unsigned int digit = (unsigned int)(*cursor - '0');

      if (value > (LIBPPD_SEMANTIC_MAX_RESOLUTION - digit) / 10U) {
        return 0;
      }
      value = value * 10U + digit;
      cursor++;
    } while (isdigit(*cursor));
  }

  return 1;
}

static int libppd_deep_cache_is_safe(ppd_file_t *ppd) {
  ppd_option_t *option;
  int index;

  for (index = 0; index < ppd->num_attrs; index++) {
    const ppd_attr_t *attr = ppd->attrs[index];

    if (strcasestr(attr->name, "resolution") &&
        (!libppd_deep_resolution_text_is_safe(attr->spec) ||
         !libppd_deep_resolution_text_is_safe(attr->value))) {
      return 0;
    }
  }

  for (option = ppdFirstOption(ppd); option; option = ppdNextOption(ppd)) {
    if (option->num_choices <= 0 || !option->choices) {
      return 0;
    }

    if (!strcasestr(option->keyword, "resolution")) {
      continue;
    }

    for (index = 0; index < option->num_choices; index++) {
      if (!libppd_deep_resolution_text_is_safe(
              option->choices[index].choice)) {
        return 0;
      }
    }
  }

  return 1;
}

static int libppd_deep_attributes_are_safe(const ppd_file_t *ppd) {
  int index;

  for (index = 0; index < ppd->num_filters; index++) {
    size_t length = strlen(ppd->filters[index]);

    if (length < 10 || length >= 1023) {
      return 0;
    }
  }

  for (index = 0; index < ppd->num_attrs; index++) {
    const ppd_attr_t *attr = ppd->attrs[index];
    const char *cursor;
    size_t items = 1;

    if (!strcasecmp(attr->name, "cupsFilter2")) {
      size_t length = strlen(attr->value);

      if (length < 10 || length >= 1023) {
        return 0;
      }
    }

    if (!strcasecmp(attr->name, "cupsUIConstraints") &&
        (!attr->spec[0] || attr->value[0] != '*')) {
      return 0;
    }

    if (strcasecmp(attr->name, "cupsUrfSupported") &&
        strncasecmp(attr->name, "cupsPwgRaster", 13) &&
        strncasecmp(attr->name, "cupsPclm", 8)) {
      continue;
    }

    for (cursor = attr->value; *cursor; cursor++) {
      if (*cursor == ',' && ++items > 20) {
        return 0;
      }
    }
  }

  return 1;
}

static int libppd_deep_make_model_is_safe(const ppd_file_t *ppd) {
  static const char *const fields[] = {
      "MFG:", "MANUFACTURER:", "MDL:", "MODEL:",
  };
  size_t index;

  if (!ppd->nickname) {
    return 0;
  }

  for (index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    const char *field = strstr(ppd->nickname, fields[index]);
    const char *value;

    if (!field || (field != ppd->nickname && field[-1] != ';')) {
      continue;
    }

    value = field + strlen(fields[index]);
    while (*value && isspace((unsigned char)*value)) {
      value++;
    }
    if (!*value || *value == ';') {
      return 0;
    }
  }

  return 1;
}
#endif

static int libppd_build_custom_mark(ppd_file_t *ppd, ppd_option_t *option,
                                    ppd_coption_t *custom, char *value,
                                    size_t value_size) {
  ppd_cparam_t *param;
  size_t used = 0;
  size_t count = 0;

  if (!strcasecmp(option->keyword, "PageSize")) {
    int length = snprintf(value, value_size, "Custom.%.9gx%.9g",
                          (double)ppd->custom_max[0],
                          (double)ppd->custom_max[1]);
    return length > 0 && (size_t)length < value_size;
  }

  if (!libppd_append(value, value_size, &used, "{")) {
    return 0;
  }

  for (param = ppdFirstCustomParam(custom);
       param && count < LIBPPD_SEMANTIC_CUSTOM_PARAMS_PER_MARK;
       param = ppdNextCustomParam(custom), count++) {
    if (!libppd_append(value, value_size, &used, "%s%s=",
                       count ? " " : "", param->name) ||
        !libppd_append_custom_value(value, value_size, &used, param)) {
      return 0;
    }
  }

  return count > 0 &&
         libppd_append(value, value_size, &used, " }");
}

static void libppd_mark_semantic_state(ppd_file_t *ppd, uint64_t hash) {
  libppd_mark_action_t regular[LIBPPD_SEMANTIC_REGULAR_MARKS];
  libppd_mark_action_t custom[LIBPPD_SEMANTIC_CUSTOM_MARKS];
  size_t regular_count = 0;
  size_t custom_count = 0;
  size_t option_index = 0;
  ppd_option_t *option;

  for (option = ppdFirstOption(ppd); option; option = ppdNextOption(ppd)) {
    ppd_coption_t *custom_option =
        ppdFindCustomOption(ppd, option->keyword);

    if (custom_option && custom_count < LIBPPD_SEMANTIC_CUSTOM_MARKS) {
      libppd_mark_action_t *action = custom + custom_count;

      snprintf(action->keyword, sizeof(action->keyword), "%s",
               option->keyword);
      if (libppd_build_custom_mark(ppd, option, custom_option, action->value,
                                   sizeof(action->value))) {
        custom_count++;
      }
    } else if (!custom_option &&
               regular_count < LIBPPD_SEMANTIC_REGULAR_MARKS &&
               option->num_choices > 0) {
      libppd_mark_action_t *action = regular + regular_count;
      size_t choice_index =
          (size_t)((hash + option_index) % (uint64_t)option->num_choices);

      snprintf(action->keyword, sizeof(action->keyword), "%s",
               option->keyword);
      snprintf(action->value, sizeof(action->value), "%s",
               option->choices[choice_index].choice);
      regular_count++;
    }
    option_index++;
  }

  for (option_index = 0; option_index < regular_count; option_index++) {
    (void)ppdMarkOption(ppd, regular[option_index].keyword,
                        regular[option_index].value);
  }
  for (option_index = 0; option_index < custom_count; option_index++) {
    (void)ppdMarkOption(ppd, custom[option_index].keyword,
                        custom[option_index].value);
  }
}

static void libppd_emit_all_sections(ppd_file_t *ppd) {
  static const ppd_section_t sections[] = {
      PPD_ORDER_ANY,      PPD_ORDER_DOCUMENT, PPD_ORDER_EXIT,
      PPD_ORDER_JCL,      PPD_ORDER_PAGE,     PPD_ORDER_PROLOG,
  };
  size_t index;

  for (index = 0; index < sizeof(sections) / sizeof(sections[0]); index++) {
    char *output = ppdEmitString(ppd, sections[index], 0.0f);
    free(output);
  }
}

#ifdef LIBPPD_SEMANTIC_DEEP_MODE
static void libppd_exercise_conflicts(ppd_file_t *ppd, uint64_t hash) {
  cups_option_t *pending = NULL;
  int num_pending = 0;
  size_t option_index = 0;
  ppd_option_t *option;

  (void)ppdConflicts(ppd);

  for (option = ppdFirstOption(ppd);
       option && option_index < LIBPPD_SEMANTIC_STATE_OPTIONS;
       option = ppdNextOption(ppd), option_index++) {
    cups_option_t *conflicts = NULL;
    const char *choice;
    int num_conflicts;
    size_t choice_index;

    if (option->num_choices <= 0) {
      continue;
    }

    choice_index =
        (size_t)((hash + option_index) % (uint64_t)option->num_choices);
    choice = option->choices[choice_index].choice;
    num_conflicts =
        ppdGetConflicts(ppd, option->keyword, choice, &conflicts);
    if (conflicts) {
      cupsFreeOptions(num_conflicts > 0 ? num_conflicts : 0, conflicts);
    }
    (void)ppdInstallableConflict(ppd, option->keyword, choice);

    if (num_pending < LIBPPD_SEMANTIC_STATE_OPTIONS) {
      num_pending =
          cupsAddOption(option->keyword, choice, num_pending, &pending);
    }
  }

  option = ppdFirstOption(ppd);
  if (option && option->num_choices > 0) {
    size_t choice_index = (size_t)(hash % (uint64_t)option->num_choices);

    (void)ppdResolveConflicts(ppd, option->keyword,
                              option->choices[choice_index].choice,
                              &num_pending, &pending);
  }
  cupsFreeOptions(num_pending, pending);
}

static int libppd_build_semantic_options(ppd_file_t *ppd, uint64_t hash,
                                         cups_option_t **options) {
  static const char *const color_modes[] = {"color", "monochrome"};
  static const char *const qualities[] = {"3", "4", "5"};
  static const char *const sides[] = {
      "one-sided", "two-sided-long-edge", "two-sided-short-edge",
  };
  ppd_option_t *option;
  ppd_attr_t *attr;
  int num_options = 0;

  if (ppd->num_sizes > 0) {
    const char *name =
        ppd->sizes[(size_t)(hash % (uint64_t)ppd->num_sizes)].name;
    num_options = cupsAddOption("media", name, num_options, options);
  }

  option = ppdFindOption(ppd, "OutputBin");
  if (option && option->num_choices > 0) {
    size_t index = (size_t)(hash % (uint64_t)option->num_choices);
    num_options = cupsAddOption("output-bin",
                                option->choices[index].choice,
                                num_options, options);
  }

  num_options =
      cupsAddOption("print-color-mode", color_modes[hash % 2U],
                    num_options, options);
  num_options =
      cupsAddOption("print-quality", qualities[hash % 3U],
                    num_options, options);
  num_options =
      cupsAddOption("sides", sides[hash % 3U], num_options, options);
  num_options = cupsAddOption("cupsBorderlessScalingFactor", "1.25",
                              num_options, options);

  attr = ppdFindAttr(ppd, "cupsIPPFinishings", NULL);
  if (attr && attr->spec[0]) {
    num_options =
        cupsAddOption("finishings", attr->spec, num_options, options);
  }

  attr = ppdFindAttr(ppd, "APPrinterPreset", NULL);
  if (attr && attr->spec[0]) {
    num_options =
        cupsAddOption("APPrinterPreset", attr->spec, num_options, options);
  }

  return num_options;
}

static void libppd_exercise_media_cache(ppd_file_t *ppd, ppd_cache_t *cache,
                                        uint64_t hash) {
  int finishing_values[16];
  int num_finishing_values;
  ppd_option_t *option;
  ppd_size_t minimum;
  ppd_size_t maximum;

  (void)ppdPageSizeLimits(ppd, &minimum, &maximum);
  ppdHandleMedia(ppd);
  (void)ppdPageSize(ppd, NULL);
  (void)ppdPageWidth(ppd, NULL);
  (void)ppdPageLength(ppd, NULL);

  if (ppd->num_sizes > 0) {
    const char *name =
        ppd->sizes[(size_t)(hash % (uint64_t)ppd->num_sizes)].name;

    (void)ppdPageSize(ppd, name);
    (void)ppdPageWidth(ppd, name);
    (void)ppdPageLength(ppd, name);
    if (cache) {
      int exact = 0;

      (void)ppdCacheGetSize(cache, name);
      (void)ppdCacheGetSize2(cache, name,
                             ppd->sizes +
                                 (size_t)(hash % (uint64_t)ppd->num_sizes));
      (void)ppdCacheGetPageSize(cache, NULL, name, &exact);
    }
  }

  if (!cache) {
    return;
  }

  option = ppdFindOption(ppd, "InputSlot");
  if (option && option->num_choices > 0) {
    char mapped[PPD_MAX_NAME];
    size_t index = (size_t)(hash % (uint64_t)option->num_choices);
    const char *source =
        ppdCacheGetSource(cache, option->choices[index].choice);

    if (source) {
      (void)ppdCacheGetInputSlot(cache, NULL, source);
      (void)ppdPwgInputSlotForSource(source, mapped, sizeof(mapped));
    }
  }

  option = ppdFindOption(ppd, "MediaType");
  if (option && option->num_choices > 0) {
    char mapped[PPD_MAX_NAME];
    size_t index = (size_t)(hash % (uint64_t)option->num_choices);
    const char *type = ppdCacheGetType(cache, option->choices[index].choice);

    if (type) {
      (void)ppdCacheGetMediaType(cache, NULL, type);
      (void)ppdPwgMediaTypeForType(type, mapped, sizeof(mapped));
    }
  }

  option = ppdFindOption(ppd, "OutputBin");
  if (option && option->num_choices > 0) {
    size_t index = (size_t)(hash % (uint64_t)option->num_choices);
    const char *bin = ppdCacheGetBin(cache, option->choices[index].choice);

    if (bin) {
      (void)ppdCacheGetOutputBin(cache, bin);
    }
  }

  num_finishing_values =
      ppdCacheGetFinishingValues(ppd, cache,
                                 (int)(sizeof(finishing_values) /
                                       sizeof(finishing_values[0])),
                                 finishing_values);
  if (num_finishing_values > 0) {
    cups_option_t *finishing_options = NULL;
    int num_finishing_options = 0;
    int index;

    for (index = 0; index < num_finishing_values; index++) {
      num_finishing_options = ppdCacheGetFinishingOptions(
          cache, NULL, (ipp_finishings_t)finishing_values[index],
          num_finishing_options, &finishing_options);
    }
    cupsFreeOptions(num_finishing_options, finishing_options);
  }
}

static void libppd_exercise_name_helpers(ppd_file_t *ppd) {
  const char *model = ppd->nickname ? ppd->nickname : ppd->modelname;
  char normalized[PPD_MAX_TEXT];
  char ppd_name[PPD_MAX_NAME];

  if (model) {
    (void)ppdNormalizeMakeAndModel(model, normalized, sizeof(normalized));
    (void)ppdHashName(model);
  }
  ppdPwgPpdizeName("output-bin", ppd_name, sizeof(ppd_name));
  ppdPwgPpdizeName("media-source", ppd_name, sizeof(ppd_name));
  ppdPwgPpdizeName("print-color-mode", ppd_name, sizeof(ppd_name));
}

static void libppd_exercise_cache_roundtrip(ppd_cache_t *cache,
                                            uint64_t hash) {
  char path[PATH_MAX];
  ppd_cache_t *loaded = NULL;
  ipp_t *loaded_attrs = NULL;
  int fd;

  if (!cache || (hash & 15U) != 0) {
    return;
  }

  fd = libppd_make_temp_ppd(path, sizeof(path));
  if (fd < 0) {
    return;
  }
  close(fd);
  unlink(path);

  if (ppdCacheWriteFile(cache, path, NULL)) {
    loaded = ppdCacheCreateWithFile(path, &loaded_attrs);
  }
  if (loaded_attrs) {
    ippDelete(loaded_attrs);
  }
  ppdCacheDestroy(loaded);
  unlink(path);
}

static void libppd_exercise_localization(ppd_file_t *ppd) {
  cups_array_t *languages;
  char buffer[PPD_MAX_TEXT];
  int index;

  languages = ppdGetLanguages(ppd);
  if (languages) {
    ppdFreeLanguages(languages);
  }

  for (index = 0; index < ppd->num_attrs &&
                  index < LIBPPD_SEMANTIC_STATE_OPTIONS;
       index++) {
    ppd_attr_t *attr = ppd->attrs[index];

    (void)ppdLocalizeAttr(ppd, attr->name,
                          attr->spec[0] ? attr->spec : NULL);
    if (!strcasecmp(attr->name, "cupsIPPReason") && attr->spec[0]) {
      (void)ppdLocalizeIPPReason(ppd, attr->spec, NULL, buffer,
                                 sizeof(buffer));
      (void)ppdLocalizeIPPReason(ppd, attr->spec, "http", buffer,
                                 sizeof(buffer));
    } else if (!strcasecmp(attr->name, "cupsMarkerName") &&
               attr->spec[0]) {
      (void)ppdLocalizeMarkerName(ppd, attr->spec);
    }
  }

  (void)ppdLocalize(ppd);
}

static void libppd_exercise_jcl(ppd_file_t *ppd, uint64_t hash) {
  char *output = NULL;
  size_t output_size = 0;
  FILE *stream = open_memstream(&output, &output_size);

  if (!stream) {
    return;
  }

  (void)ppdEmitJCL(ppd, stream, (int)(hash & 0x7fffffffU), "fuzz-user",
                   "smbprn.00000042 FuzzApp - SemanticJob");
  (void)ppdEmitJCLPDF(ppd, stream, (int)(hash & 0x7fffffffU), "fuzz-user",
                      "SemanticPDF", (int)(hash % 4U) + 1,
                      (hash & 4U) != 0);
  (void)ppdEmitJCLEnd(ppd, stream);
  fclose(stream);
  free(output);
}

static void libppd_exercise_ipp_bridge(ppd_file_t *ppd,
                                       ipp_t *printer_attrs,
                                       uint64_t hash) {
  static const char *const media_supported_values[] = {
      "media-left-margin",
      "media-bottom-margin",
      "media-right-margin",
      "media-top-margin",
      "media-source",
      "media-type",
  };
  static const char *const handling_supported_values[] = {
      "separate-documents-uncollated-copies",
      "separate-documents-collated-copies",
  };
  static const char *const color_supported_values[] = {
      "auto",
      "color",
      "monochrome",
  };
  static const char *const media_values[] = {
      "{media-size-name=na_letter_8.5x11in media-source=main "
      "media-type=stationery}",
      "{media-size={x-dimension=21000 y-dimension=29700} "
      "media-source=manual media-type=photographic-glossy}",
  };
  static const char *const sides_values[] = {
      "one-sided",
      "two-sided-long-edge",
      "two-sided-short-edge",
  };
  static const char *const color_values[] = {
      "monochrome",
      "color",
  };
  cups_option_t *options = NULL;
  ipp_attribute_t *color_supported;
  ipp_attribute_t *handling_supported;
  ipp_attribute_t *media_supported;
  ipp_t *job_attrs;
  ipp_t *request;
  ipp_t *support_attrs;
  int num_options;

  if (!printer_attrs || !ppd->cache) {
    return;
  }

  support_attrs = ippNew();
  if (!support_attrs) {
    return;
  }

  media_supported = ippFindAttribute(
      printer_attrs, "media-col-supported", IPP_TAG_ZERO);
  if (!media_supported) {
    media_supported = ippAddStrings(
        support_attrs, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
        "media-col-supported",
        (int)(sizeof(media_supported_values) /
              sizeof(media_supported_values[0])),
        NULL, media_supported_values);
  }
  handling_supported = ippFindAttribute(
      printer_attrs, "multiple-document-handling-supported", IPP_TAG_ZERO);
  if (!handling_supported) {
    handling_supported = ippAddStrings(
        support_attrs, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
        "multiple-document-handling-supported",
        (int)(sizeof(handling_supported_values) /
              sizeof(handling_supported_values[0])),
        NULL, handling_supported_values);
  }
  color_supported = ippFindAttribute(
      printer_attrs, "print-color-mode-supported", IPP_TAG_ZERO);
  if (!color_supported) {
    color_supported = ippAddStrings(
        support_attrs, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
        "print-color-mode-supported",
        (int)(sizeof(color_supported_values) /
              sizeof(color_supported_values[0])),
        NULL, color_supported_values);
  }
  if (!media_supported || !handling_supported || !color_supported) {
    ippDelete(support_attrs);
    return;
  }

  job_attrs = ippNew();
  request = ippNewRequest(IPP_OP_PRINT_JOB);
  if (!job_attrs || !request) {
    ippDelete(request);
    ippDelete(job_attrs);
    ippDelete(support_attrs);
    return;
  }

  ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-col", NULL,
               media_values[hash % 2U]);
  ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "output-bin", NULL,
               (hash & 2U) ? "face-up" : "standard-bin");
  ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "sides", NULL,
               sides_values[hash % 3U]);
  ippAddInteger(job_attrs, IPP_TAG_JOB, IPP_TAG_ENUM, "print-quality",
                (int)(IPP_QUALITY_DRAFT + (hash % 3U)));
  ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "print-color-mode",
               NULL, color_values[hash % 2U]);
  ippAddInteger(job_attrs, IPP_TAG_JOB, IPP_TAG_ENUM, "finishings",
                IPP_FINISHINGS_NONE);

  num_options = ppdGetOptions(&options, printer_attrs, job_attrs, ppd);
  num_options =
      cupsAddOption("collate", (hash & 4U) ? "true" : "false",
                    num_options, &options);
  num_options = cupsAddOption("number-up", (hash & 8U) ? "2" : "1",
                              num_options, &options);
  num_options = cupsAddOption("job-pages", (hash & 16U) ? "3" : "1",
                              num_options, &options);
  num_options = cupsAddOption("job-password", "1234", num_options,
                              &options);
  num_options = cupsAddOption("job-password-encryption", "none",
                              num_options, &options);
  num_options = cupsAddOption("job-account-id", "fuzz-account",
                              num_options, &options);
  num_options = cupsAddOption("job-accounting-user-id", "fuzz-user",
                              num_options, &options);

  (void)ppdConvertOptions(
      request, ppd, ppd->cache, media_supported, handling_supported,
      color_supported, "fuzz-user",
      (hash & 32U) ? "application/pdf" : "application/postscript",
      (int)(hash % 4U) + 1, num_options, options);

  cupsFreeOptions(num_options, options);
  {
    ipp_attribute_t *media_attr =
        ippFindAttribute(request, "media-col", IPP_TAG_BEGIN_COLLECTION);
    ipp_t *media_col = media_attr ? ippGetCollection(media_attr, 0) : NULL;
    ipp_attribute_t *size_attr =
        media_col ? ippFindAttribute(media_col, "media-size",
                                     IPP_TAG_BEGIN_COLLECTION)
                  : NULL;
    ipp_t *media_size = size_attr ? ippGetCollection(size_attr, 0) : NULL;

    /*
     * ppdConvertOptions adds references to both collections but retains their
     * creator references. Drop only those omitted creator references here;
     * the request still owns the normal collection graph until ippDelete.
     */
    ippDelete(media_size);
    ippDelete(media_col);
  }
  ippDelete(request);
  ippDelete(job_attrs);
  ippDelete(support_attrs);
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char path[PATH_MAX];
  ppd_file_t *ppd = NULL;
  ppd_cache_t *cache = NULL;
  ipp_t *attrs = NULL;
  cups_option_t *semantic_options = NULL;
  cups_page_header_t header;
  uint64_t hash;
  int fd;
  int num_semantic_options = 0;

  if (size > LIBPPD_SEMANTIC_MAX_INPUT) {
    return 0;
  }

  fd = libppd_make_temp_ppd(path, sizeof(path));
  if (fd < 0) {
    return 0;
  }
  if (libppd_write_all(fd, data, size) != 0) {
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

  if (!libppd_within_work_budget(ppd)) {
    ppdClose(ppd);
    return 0;
  }

#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  if (!libppd_deep_custom_page_is_safe(ppd)) {
    ppdClose(ppd);
    return 0;
  }
#endif

  hash = libppd_hash(data, size);
  ppdMarkDefaults(ppd);
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  if (libppd_deep_cache_is_safe(ppd) &&
      libppd_deep_attributes_are_safe(ppd)) {
    num_semantic_options =
        libppd_build_semantic_options(ppd, hash, &semantic_options);
    (void)ppdMarkOptions(ppd, num_semantic_options, semantic_options);
    libppd_mark_semantic_state(ppd, hash);
  }
#else
  libppd_mark_semantic_state(ppd, hash);
#endif

#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  if (libppd_deep_cache_is_safe(ppd) &&
      libppd_deep_attributes_are_safe(ppd)) {
#endif
    cache = ppdCacheCreateWithPPD(ppd);
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
    libppd_exercise_media_cache(ppd, cache, hash);
    libppd_exercise_cache_roundtrip(cache, hash);
#endif
    ppdCacheDestroy(cache);
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  }
#endif

#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  if (libppd_deep_cache_is_safe(ppd) &&
      libppd_deep_attributes_are_safe(ppd) &&
      libppd_deep_make_model_is_safe(ppd)) {
#endif
    attrs = ppdLoadAttributes(ppd);
    if (attrs) {
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
      libppd_exercise_ipp_bridge(ppd, attrs, hash);
#endif
      ippDelete(attrs);
    }
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  }
#endif

  /* Cache construction restores defaults, so reapply the same public marks. */
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  if (libppd_deep_cache_is_safe(ppd) &&
      libppd_deep_attributes_are_safe(ppd)) {
    libppd_mark_semantic_state(ppd, hash);
    libppd_exercise_conflicts(ppd, hash);
  }
#else
  libppd_mark_semantic_state(ppd, hash);
#endif
  libppd_emit_all_sections(ppd);
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  libppd_exercise_jcl(ppd, hash);
  libppd_exercise_localization(ppd);
  libppd_exercise_name_helpers(ppd);
#endif
  (void)ppdRasterInterpretPPD(&header, ppd, num_semantic_options,
                              semantic_options, NULL);
#ifdef LIBPPD_SEMANTIC_DEEP_MODE
  {
    double margins[4];
    double dimensions[2];
    int image_fit = 0;
    int landscape = 0;

    (void)ppdRasterMatchPPDSize(&header, ppd, margins, dimensions, &image_fit,
                                &landscape);
  }
#endif

  cupsFreeOptions(num_semantic_options, semantic_options);
  ppdClose(ppd);
  return 0;
}
