// SPDX-License-Identifier: Apache-2.0
#include "../include/job.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CF_V2_JOB_MAX_PPD
#define CF_V2_JOB_MAX_PPD (256U * 1024U)
#endif
#ifndef CF_V2_JOB_MAX_OPTIONS
#define CF_V2_JOB_MAX_OPTIONS (16U * 1024U)
#endif
#ifndef CF_V2_JOB_MAX_TITLE
#define CF_V2_JOB_MAX_TITLE (4U * 1024U)
#endif
#ifndef CF_V2_JOB_MAX_DOCUMENT
#define CF_V2_JOB_MAX_DOCUMENT (4U * 1024U * 1024U)
#endif
#ifndef CF_V2_JOB_OPTION_MASK
#define CF_V2_JOB_OPTION_MASK UINT32_MAX
#endif

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t cf_v2_job_random(uint32_t *state) {
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);
  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  *state = value;
  return value;
}

static size_t cf_v2_job_mutate_region(uint8_t *data, size_t size,
                                      size_t max_size, size_t offset,
                                      size_t region_size, size_t suffix_size,
                                      size_t region_limit) {
  uint8_t *temporary;
  size_t available;
  size_t copy_size;
  size_t new_region_size;

  if (offset > size || region_size > size - offset ||
      suffix_size != size - offset - region_size || max_size < offset) {
    return region_size;
  }
  available = max_size - offset;
  if (available < suffix_size) {
    return region_size;
  }
  available -= suffix_size;
  if (available > region_limit) {
    available = region_limit;
  }
  temporary = (uint8_t *)malloc(available ? available : 1U);
  if (!temporary) {
    return region_size;
  }
  copy_size = region_size < available ? region_size : available;
  memcpy(temporary, data + offset, copy_size);
  new_region_size = LLVMFuzzerMutate(temporary, copy_size, available);
  memmove(data + offset + new_region_size, data + offset + region_size,
          suffix_size);
  memcpy(data + offset, temporary, new_region_size);
  free(temporary);
  return new_region_size;
}

typedef struct cf_v2_job_numeric_option_s {
  const char *name;
  const char *suffix;
} cf_v2_job_numeric_option_t;

static const cf_v2_job_numeric_option_t cf_v2_job_numeric_options[] = {
    {"natural-scaling", ""}, {"scaling", ""},
    {"ppi", ""},             {"number-up", ""},
    {"columns", ""},         {"cpi", ""},
    {"lpi", ""},             {"PageWidth", ""},
    {"PageHeight", ""},      {"PageLeft", ""},
    {"TabWidth", ""},        {"Resolution", "dpi"},
};

/* Generic parser and arithmetic boundaries, independent of a specific bug. */
static const char *const cf_v2_job_numeric_boundaries[] = {
    "0",          "1",          "2",          "4",
    "8",          "15",         "16",         "17",
    "18",         "19",         "31",         "32",
    "63",         "64",         "127",        "128",
    "255",        "256",        "1023",       "1024",
    "32767",      "32768",      "65535",      "65536",
    "16777215",   "16777216",   "1073741824", "2147483647",
    "2147483648", "4294967295",
};

#ifdef CF_V2_JOB_HISTORICAL_BOUNDARIES
/*
 * Campaign-only transition values. They prove that a route can retain all
 * other valid job blocks while one semantic field crosses a known boundary.
 * They are deliberately excluded from normal OSS-Fuzz builds.
 */
typedef struct cf_v2_job_historical_option_s {
  const char *name;
  const char *value;
} cf_v2_job_historical_option_t;

static const cf_v2_job_historical_option_t cf_v2_job_historical_options[] = {
    {"natural-scaling", "50489"},
    {"natural-scaling", "74820853"},
    {"Resolution", "9942054"},
    {"number-up", "19"},
    {"columns", "429496747"},
    {"PageWidth", "1073741824"},
};

static const char *const cf_v2_job_historical_safe_values[] = {
    "1", "2", "4", "16", "100", "300",
};
#endif

static int cf_v2_job_option_space(uint8_t byte) {
  return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n';
}

static int cf_v2_job_find_option(const uint8_t *options, size_t options_size,
                                 const char *name, size_t *match_offset,
                                 size_t *match_size) {
  size_t cursor = 0U;
  size_t name_size = strlen(name);

  while (cursor < options_size) {
    size_t token_start;
    size_t token_end;

    while (cursor < options_size && cf_v2_job_option_space(options[cursor]))
      cursor ++;
    token_start = cursor;
    while (cursor < options_size && !cf_v2_job_option_space(options[cursor]))
      cursor ++;
    token_end = cursor;
    if (token_end - token_start > name_size &&
        !memcmp(options + token_start, name, name_size) &&
        options[token_start + name_size] == '=') {
      if (match_offset)
        *match_offset = token_start;
      if (match_size)
        *match_size = token_end - token_start;
      return 1;
    }
  }
  return 0;
}

static int cf_v2_job_option_enabled(size_t index) {
  return index < 32U && (CF_V2_JOB_OPTION_MASK & (UINT32_C(1) << index));
}

static const char *cf_v2_job_pick_numeric_boundary(
    const cf_v2_job_numeric_option_t *option, const uint8_t *document,
    size_t document_size, uint32_t *random_state) {
#if defined(CF_V2_JOB_HISTORICAL_BOUNDARIES) && \
    defined(CF_V2_JOB_RELATION_IMAGE_PDF)
  if (!strcmp(option->name, "natural-scaling")) {
    uint32_t width;
    uint32_t height;

    if (document_size < 24U ||
        memcmp(document, "\x89PNG\r\n\x1a\n", 8U) ||
        memcmp(document + 12U, "IHDR", 4U))
      return "100";
    width = ((uint32_t)document[16] << 24) |
            ((uint32_t)document[17] << 16) |
            ((uint32_t)document[18] << 8) | document[19];
    height = ((uint32_t)document[20] << 24) |
             ((uint32_t)document[21] << 16) |
             ((uint32_t)document[22] << 8) | document[23];
    return width == 139U && height == 199U ? "74820853" : "100";
  }
#else
  (void)document;
  (void)document_size;
#endif
#ifdef CF_V2_JOB_HISTORICAL_BOUNDARIES
  size_t start = cf_v2_job_random(random_state) %
                 (sizeof(cf_v2_job_historical_options) /
                  sizeof(cf_v2_job_historical_options[0]));
  size_t index;

  for (index = 0U;
       index < sizeof(cf_v2_job_historical_options) /
                   sizeof(cf_v2_job_historical_options[0]);
       index ++) {
    const cf_v2_job_historical_option_t *historical =
        &cf_v2_job_historical_options[
            (start + index) %
            (sizeof(cf_v2_job_historical_options) /
             sizeof(cf_v2_job_historical_options[0]))];

    if (!strcmp(option->name, historical->name))
      return historical->value;
  }
  return cf_v2_job_historical_safe_values[
      cf_v2_job_random(random_state) %
      (sizeof(cf_v2_job_historical_safe_values) /
       sizeof(cf_v2_job_historical_safe_values[0]))];
#else
  return cf_v2_job_numeric_boundaries[
      cf_v2_job_random(random_state) %
      (sizeof(cf_v2_job_numeric_boundaries) /
       sizeof(cf_v2_job_numeric_boundaries[0]))];
#endif
}

static size_t cf_v2_job_mutate_semantic_option(
    uint8_t *data, size_t size, size_t max_size, size_t options_offset,
    size_t options_size, size_t suffix_size, const uint8_t *document,
    size_t document_size, uint32_t *random_state) {
  const cf_v2_job_numeric_option_t *option;
  const char *value;
  uint8_t *temporary;
  size_t cursor = 0U;
  size_t replace_offset = options_size;
  size_t replace_size = 0U;
  size_t name_size;
  size_t value_size;
  size_t suffix_length;
  size_t token_size;
  size_t separator_size = 0U;
  size_t new_options_size;
  size_t output_size;
  size_t option_index;

  if (options_offset > size || options_size > size - options_offset ||
      suffix_size != size - options_offset - options_size) {
    return size;
  }
  option_index = cf_v2_job_random(random_state) %
                 (sizeof(cf_v2_job_numeric_options) /
                  sizeof(cf_v2_job_numeric_options[0]));
  for (cursor = 0U;
       cursor < sizeof(cf_v2_job_numeric_options) /
                    sizeof(cf_v2_job_numeric_options[0]);
       cursor ++) {
    size_t candidate_index =
        (option_index + cursor) %
        (sizeof(cf_v2_job_numeric_options) /
         sizeof(cf_v2_job_numeric_options[0]));

    if (cf_v2_job_option_enabled(candidate_index)) {
      option_index = candidate_index;
      break;
    }
  }
  if (cursor == sizeof(cf_v2_job_numeric_options) /
                    sizeof(cf_v2_job_numeric_options[0]))
    return size;
  option = &cf_v2_job_numeric_options[option_index];
  if ((cf_v2_job_random(random_state) & 3U) != 0U) {
    size_t index;

    for (index = 0U;
         index < sizeof(cf_v2_job_numeric_options) /
                     sizeof(cf_v2_job_numeric_options[0]);
         index ++) {
      size_t candidate_index =
          (option_index + index) %
          (sizeof(cf_v2_job_numeric_options) /
           sizeof(cf_v2_job_numeric_options[0]));
      const cf_v2_job_numeric_option_t *candidate;

      if (!cf_v2_job_option_enabled(candidate_index))
        continue;
      candidate = &cf_v2_job_numeric_options[candidate_index];
      if (cf_v2_job_find_option(data + options_offset, options_size,
                                candidate->name, NULL, NULL)) {
        option = candidate;
        break;
      }
    }
  }
  value = cf_v2_job_pick_numeric_boundary(option, document, document_size,
                                           random_state);
  name_size = strlen(option->name);
  value_size = strlen(value);
  suffix_length = strlen(option->suffix);
  if (name_size > SIZE_MAX - value_size - suffix_length - 1U)
    return size;
  token_size = name_size + 1U + value_size + suffix_length;

  (void)cf_v2_job_find_option(data + options_offset, options_size,
                              option->name, &replace_offset, &replace_size);

  if (!replace_size && options_size &&
      !cf_v2_job_option_space(data[options_offset + options_size - 1U]))
    separator_size = 1U;
  if (options_size - replace_size >
      CF_V2_JOB_MAX_OPTIONS - token_size - separator_size)
    return size;
  new_options_size =
      options_size - replace_size + separator_size + token_size;
  if (new_options_size > max_size ||
      size - options_size > max_size - new_options_size)
    return size;
  output_size = size - options_size + new_options_size;

  temporary = (uint8_t *)malloc(new_options_size ? new_options_size : 1U);
  if (!temporary)
    return size;
  if (replace_offset)
    memcpy(temporary, data + options_offset, replace_offset);
  cursor = replace_offset;
  if (!replace_size && separator_size)
    temporary[cursor ++] = ' ';
  memcpy(temporary + cursor, option->name, name_size);
  cursor += name_size;
  temporary[cursor ++] = '=';
  memcpy(temporary + cursor, value, value_size);
  cursor += value_size;
  memcpy(temporary + cursor, option->suffix, suffix_length);
  cursor += suffix_length;
  if (replace_size) {
    size_t tail_offset = replace_offset + replace_size;
    size_t tail_size = options_size - tail_offset;

    if (tail_size)
      memcpy(temporary + cursor, data + options_offset + tail_offset,
             tail_size);
  }

  memmove(data + options_offset + new_options_size,
          data + options_offset + options_size, suffix_size);
  memcpy(data + options_offset, temporary, new_options_size);
  free(temporary);
  cf_v2_job_store_u32le(data + 4U, (uint32_t)new_options_size);
  return output_size;
}

#if defined(CF_V2_JOB_PPD_SEMANTIC) || defined(CF_V2_JOB_PPD_ONLY)
static size_t cf_v2_job_mutate_semantic_ppd(
    uint8_t *data, size_t size, size_t max_size, size_t ppd_offset,
    size_t ppd_size, size_t suffix_size, uint32_t *random_state) {
  static const char marker[] = "*cupsPclmStripHeightPreferred:";
  static const char *const values[] = {
      "0", "1", "2", "15", "16", "17", "255", "256",
  };
  const char *value = values[cf_v2_job_random(random_state) %
                             (sizeof(values) / sizeof(values[0]))];
  size_t marker_size = sizeof(marker) - 1U;
  size_t value_size = strlen(value);
  size_t marker_offset;
  size_t value_offset;
  size_t old_value_size;
  size_t new_ppd_size;
  size_t output_size;

  if (ppd_offset > size || ppd_size > size - ppd_offset ||
      suffix_size != size - ppd_offset - ppd_size ||
      ppd_size < marker_size)
    return size;
  for (marker_offset = 0U; marker_offset <= ppd_size - marker_size;
       marker_offset ++) {
    if (!memcmp(data + ppd_offset + marker_offset, marker, marker_size))
      break;
  }
  if (marker_offset > ppd_size - marker_size) {
    uint8_t line[96];
    int written = snprintf((char *)line, sizeof(line), "%s \"%s\"\n",
                           marker, value);
    size_t line_size;

    if (written <= 0 || (size_t)written >= sizeof(line))
      return size;
    line_size = (size_t)written;
    if (line_size > CF_V2_JOB_MAX_PPD || line_size > max_size ||
        ppd_size > CF_V2_JOB_MAX_PPD - line_size ||
        size > max_size - line_size)
      return size;
    memmove(data + ppd_offset + ppd_size + line_size,
            data + ppd_offset + ppd_size, suffix_size);
    memcpy(data + ppd_offset + ppd_size, line, line_size);
    new_ppd_size = ppd_size + line_size;
    cf_v2_job_store_u32le(data, (uint32_t)new_ppd_size);
    return size + line_size;
  }
  value_offset = marker_offset + marker_size;
  while (value_offset < ppd_size &&
         (data[ppd_offset + value_offset] == ' ' ||
          data[ppd_offset + value_offset] == '\t'))
    value_offset ++;
  if (value_offset >= ppd_size || data[ppd_offset + value_offset] != '"')
    return size;
  value_offset ++;
  old_value_size = 0U;
  while (value_offset + old_value_size < ppd_size &&
         data[ppd_offset + value_offset + old_value_size] != '"' &&
         data[ppd_offset + value_offset + old_value_size] != '\n' &&
         data[ppd_offset + value_offset + old_value_size] != '\r')
    old_value_size ++;
  if (value_offset + old_value_size >= ppd_size ||
      data[ppd_offset + value_offset + old_value_size] != '"')
    return size;
  if (ppd_size - old_value_size > CF_V2_JOB_MAX_PPD - value_size ||
      size - old_value_size > max_size - value_size)
    return size;
  new_ppd_size = ppd_size - old_value_size + value_size;
  output_size = size - old_value_size + value_size;
  memmove(data + ppd_offset + value_offset + value_size,
          data + ppd_offset + value_offset + old_value_size,
          ppd_size - value_offset - old_value_size + suffix_size);
  memcpy(data + ppd_offset + value_offset, value, value_size);
  cf_v2_job_store_u32le(data, (uint32_t)new_ppd_size);
  return output_size;
}
#endif

#if defined(CF_V2_JOB_RASTER_SEMANTIC) || defined(CF_V2_JOB_RASTER_ONLY)
#define CF_V2_RASTER_HEADER_SIZE 1796U
#define CF_V2_RASTER_WIDTH_OFFSET 372U
#define CF_V2_RASTER_HEIGHT_OFFSET 376U
#define CF_V2_RASTER_BITS_PER_COLOR_OFFSET 384U
#define CF_V2_RASTER_BITS_PER_PIXEL_OFFSET 388U
#define CF_V2_RASTER_BYTES_PER_LINE_OFFSET 392U
#define CF_V2_RASTER_COLOR_ORDER_OFFSET 396U
#define CF_V2_RASTER_COLOR_SPACE_OFFSET 400U
#define CF_V2_RASTER_COMPRESSION_OFFSET 404U
#define CF_V2_RASTER_ROW_COUNT_OFFSET 408U
#define CF_V2_RASTER_ROW_FEED_OFFSET 412U
#define CF_V2_RASTER_ROW_STEP_OFFSET 416U
#define CF_V2_RASTER_NUM_COLORS_OFFSET 420U

typedef struct cf_v2_job_raster_profile_s {
  uint32_t bits_per_color;
  uint32_t bits_per_pixel;
  uint32_t color_space;
  uint32_t num_colors;
} cf_v2_job_raster_profile_t;

static size_t cf_v2_job_mutate_semantic_raster(
    uint8_t *data, size_t size, size_t max_size, size_t document_offset,
    size_t document_size, uint32_t *random_state) {
  static const uint32_t widths[] = {
      1U, 7U, 8U, 15U, 16U, 31U, 32U, 63U, 64U, 127U, 128U,
  };
  static const cf_v2_job_raster_profile_t profiles[] = {
      {1U, 1U, 3U, 1U},   /* packed K */
      {8U, 8U, 3U, 1U},   /* byte K */
      {8U, 8U, 18U, 1U},  /* sGray */
      {16U, 16U, 18U, 1U},
      {8U, 24U, 19U, 3U}, /* sRGB */
  };
  const cf_v2_job_raster_profile_t *profile;
  uint8_t header[CF_V2_RASTER_HEADER_SIZE];
  uint32_t width;
  uint32_t height;
  uint32_t bytes_per_line;
  uint32_t unit_bytes;
  uint32_t units_per_row;
  size_t chunks_per_row;
  size_t encoded_row_size;
  size_t new_document_size;
  size_t output_size;
  size_t cursor;
  uint32_t row;

  if (document_offset > size || document_size != size - document_offset ||
      document_size < 4U + CF_V2_RASTER_HEADER_SIZE ||
      memcmp(data + document_offset, "2SaR", 4U))
    return size;

  profile = &profiles[cf_v2_job_random(random_state) %
                      (sizeof(profiles) / sizeof(profiles[0]))];
  width = widths[cf_v2_job_random(random_state) %
                 (sizeof(widths) / sizeof(widths[0]))];
  height = 1U + (cf_v2_job_random(random_state) & 1U);
  bytes_per_line = (width * profile->bits_per_pixel + 7U) / 8U;
  unit_bytes = profile->bits_per_pixel >= 8U
                   ? profile->bits_per_pixel / 8U
                   : 1U;
  units_per_row = profile->bits_per_pixel >= 8U ? width : bytes_per_line;
  chunks_per_row = (units_per_row + 127U) / 128U;
  if (!bytes_per_line || !unit_bytes || !units_per_row ||
      bytes_per_line > SIZE_MAX - 1U - chunks_per_row)
    return size;
  encoded_row_size = 1U + chunks_per_row + bytes_per_line;
  if (encoded_row_size >
      (CF_V2_JOB_MAX_DOCUMENT - 4U - CF_V2_RASTER_HEADER_SIZE) / height)
    return size;
  new_document_size =
      4U + CF_V2_RASTER_HEADER_SIZE + encoded_row_size * height;
  if (new_document_size > max_size ||
      size - document_size > max_size - new_document_size)
    return size;
  output_size = size - document_size + new_document_size;

  memcpy(header, data + document_offset + 4U, sizeof(header));
  cf_v2_job_store_u32le(header + CF_V2_RASTER_WIDTH_OFFSET, width);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_HEIGHT_OFFSET, height);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_BITS_PER_COLOR_OFFSET,
                        profile->bits_per_color);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_BITS_PER_PIXEL_OFFSET,
                        profile->bits_per_pixel);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_BYTES_PER_LINE_OFFSET,
                        bytes_per_line);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_COLOR_ORDER_OFFSET, 0U);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_COLOR_SPACE_OFFSET,
                        profile->color_space);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_COMPRESSION_OFFSET, 0U);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_ROW_COUNT_OFFSET, height);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_ROW_FEED_OFFSET, 0U);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_ROW_STEP_OFFSET, 0U);
  cf_v2_job_store_u32le(header + CF_V2_RASTER_NUM_COLORS_OFFSET,
                        profile->num_colors);

  memcpy(data + document_offset, "2SaR", 4U);
  memcpy(data + document_offset + 4U, header, sizeof(header));
  cursor = document_offset + 4U + sizeof(header);
  for (row = 0U; row < height; row ++) {
    uint32_t remaining = units_per_row;
    uint32_t sample = row * 53U + width + profile->bits_per_pixel;

    data[cursor ++] = 0U; /* This encoded row occurs once. */
    while (remaining) {
      uint32_t count = remaining > 128U ? 128U : remaining;
      size_t literal_size = (size_t)count * unit_bytes;
      size_t index;

      data[cursor ++] = count == 1U ? 0U : (uint8_t)(257U - count);
      for (index = 0U; index < literal_size; index ++)
        data[cursor ++] = (uint8_t)(sample + index * 73U);
      remaining -= count;
      sample += (uint32_t)literal_size;
    }
  }
  cf_v2_job_store_u32le(data + 12U, (uint32_t)new_document_size);
  return output_size;
}
#endif

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned seed) {
  cf_v2_job_input_t input;
  uint32_t random_state = seed;
  size_t offsets[4];
  size_t lengths[4];
  size_t limits[4] = {CF_V2_JOB_MAX_PPD, CF_V2_JOB_MAX_OPTIONS,
                      CF_V2_JOB_MAX_TITLE, CF_V2_JOB_MAX_DOCUMENT};
  size_t suffix_size;
  size_t new_length;
  size_t output_size;
  unsigned lane;

  if (!cf_v2_parse_job_input(data, size, CF_V2_JOB_MAX_PPD,
                             CF_V2_JOB_MAX_OPTIONS, CF_V2_JOB_MAX_TITLE,
                             CF_V2_JOB_MAX_DOCUMENT, &input)) {
    return LLVMFuzzerMutate(data, size, max_size);
  }

  offsets[0] = CF_V2_JOB_FIXED_SIZE;
  lengths[0] = input.ppd_size;
  offsets[1] = offsets[0] + lengths[0];
  lengths[1] = input.options_size;
  offsets[2] = offsets[1] + lengths[1];
  lengths[2] = input.title_size;
  offsets[3] = offsets[2] + lengths[2];
  lengths[3] = input.document_size;

#ifdef CF_V2_JOB_OPTIONS_ONLY
  /* Experimental isolation mode: preserve PPD/document validity. */
  lane = 5U;
#elif defined(CF_V2_JOB_PPD_ONLY)
  lane = 6U;
#elif defined(CF_V2_JOB_RASTER_ONLY)
#if defined(CF_V2_JOB_PPD_SEMANTIC)
  lane = 7U;
#else
  lane = 6U;
#endif
#elif defined(CF_V2_JOB_PPD_SEMANTIC) && \
    defined(CF_V2_JOB_RASTER_SEMANTIC)
  lane = cf_v2_job_random(&random_state) % 8U;
#elif defined(CF_V2_JOB_PPD_SEMANTIC)
  lane = cf_v2_job_random(&random_state) % 7U;
#elif defined(CF_V2_JOB_RASTER_SEMANTIC)
  lane = cf_v2_job_random(&random_state) % 7U;
#else
  lane = cf_v2_job_random(&random_state) % 6U;
#endif
#ifdef CF_V2_JOB_LOCK_PPD
  if (lane == 0U) {
#if defined(CF_V2_JOB_RASTER_SEMANTIC) || defined(CF_V2_JOB_RASTER_ONLY)
#if defined(CF_V2_JOB_PPD_SEMANTIC)
    lane = 7U;
#else
    lane = 6U;
#endif
#else
    lane = 4U;
#endif
  }
#endif
  if (lane == 5U) {
    suffix_size = size - offsets[1] - lengths[1];
    return cf_v2_job_mutate_semantic_option(
        data, size, max_size, offsets[1], lengths[1], suffix_size,
        input.document, input.document_size, &random_state);
  }
#if defined(CF_V2_JOB_PPD_SEMANTIC) || defined(CF_V2_JOB_PPD_ONLY)
  if (lane == 6U) {
    suffix_size = size - offsets[0] - lengths[0];
    return cf_v2_job_mutate_semantic_ppd(
        data, size, max_size, offsets[0], lengths[0], suffix_size,
        &random_state);
  }
#endif
#if defined(CF_V2_JOB_RASTER_SEMANTIC) || defined(CF_V2_JOB_RASTER_ONLY)
#if defined(CF_V2_JOB_PPD_SEMANTIC)
  if (lane == 7U) {
#else
  if (lane == 6U) {
#endif
    return cf_v2_job_mutate_semantic_raster(
        data, size, max_size, offsets[3], lengths[3], &random_state);
  }
#endif
  if (lane == 4U) {
    size_t offset = CF_V2_JOB_HEADER_SIZE +
                    cf_v2_job_random(&random_state) % CF_V2_CONTROL_SIZE;
    data[offset] ^=
        (uint8_t)(1U << (cf_v2_job_random(&random_state) % 8U));
    return size;
  }

  suffix_size = size - offsets[lane] - lengths[lane];
  new_length = cf_v2_job_mutate_region(
      data, size, max_size, offsets[lane], lengths[lane], suffix_size,
      limits[lane]);
  output_size = size - lengths[lane] + new_length;

  if (lane == 0U) {
    if (new_length < CF_V2_JOB_PPD_PREFIX_SIZE) {
      size_t growth = CF_V2_JOB_PPD_PREFIX_SIZE - new_length;
      if (output_size + growth > max_size ||
          new_length + growth > limits[lane]) {
        cf_v2_job_store_u32le(data, (uint32_t)new_length);
        return output_size;
      }
      memmove(data + offsets[lane] + CF_V2_JOB_PPD_PREFIX_SIZE,
              data + offsets[lane] + new_length, suffix_size);
      new_length += growth;
      output_size += growth;
    }
    memcpy(data + offsets[lane], CF_V2_JOB_PPD_PREFIX,
           CF_V2_JOB_PPD_PREFIX_SIZE);
  } else if (lane == 1U) {
    for (size_t index = 0; index < new_length; index++) {
      if (!data[offsets[lane] + index]) {
        data[offsets[lane] + index] = ' ';
      }
    }
  } else if (lane == 3U && !new_length) {
    if (output_size >= max_size) {
      cf_v2_job_store_u32le(data + lane * 4U, 0U);
      return output_size;
    }
    memmove(data + offsets[lane] + 1U, data + offsets[lane], suffix_size);
    data[offsets[lane]] = 0;
    new_length = 1U;
    output_size++;
  }

  cf_v2_job_store_u32le(data + lane * 4U, (uint32_t)new_length);
  return output_size;
}

static int cf_v2_job_blocks_from_bytes(const uint8_t *data, size_t size,
                                       cf_v2_shared_block_set_t *blocks) {
  cf_v2_job_input_t input;

  return cf_v2_parse_job_input(data, size, CF_V2_JOB_MAX_PPD,
                               CF_V2_JOB_MAX_OPTIONS, CF_V2_JOB_MAX_TITLE,
                               CF_V2_JOB_MAX_DOCUMENT, &input) &&
         cf_v2_job_shared_blocks(&input, blocks);
}

static void cf_v2_job_take_block(cf_v2_shared_block_set_t *output,
                                 const cf_v2_shared_block_set_t *donor,
                                 cf_v2_shared_block_role_t role) {
  const cf_v2_shared_block_t *replacement =
      cf_v2_shared_blocks_find(donor, role);

  if (replacement)
    (void)cf_v2_shared_blocks_replace(output, replacement);
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                 const uint8_t *data2, size_t size2,
                                 uint8_t *out, size_t max_out_size,
                                 unsigned int seed) {
  cf_v2_shared_block_set_t first;
  cf_v2_shared_block_set_t second;
  cf_v2_shared_block_set_t selected;
  const cf_v2_shared_block_set_t *base;
  const cf_v2_shared_block_set_t *donor;
  uint32_t random_state = seed;
  int valid1;
  int valid2;
  size_t output_size;

  if (!out)
    return 0U;
  valid1 = cf_v2_job_blocks_from_bytes(data1, size1, &first);
  valid2 = cf_v2_job_blocks_from_bytes(data2, size2, &second);
  if (!valid1 && !valid2)
    return 0U;
  if (valid1 && size1 <= max_out_size &&
      (!valid2 || size2 > max_out_size ||
       !(cf_v2_job_random(&random_state) & 1U))) {
    base = &first;
    donor = valid2 ? &second : &first;
  } else if (valid2 && size2 <= max_out_size) {
    base = &second;
    donor = valid1 ? &first : &second;
  } else {
    return 0U;
  }
  selected = *base;

  /* Keep useful subgraphs intact, then vary the relation between them. */
  switch (cf_v2_job_random(&random_state) % 4U) {
    case 0U:
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_PPD);
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_OPTIONS);
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_CONTROL);
      break;
    case 1U:
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_TITLE);
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_DOCUMENT);
      break;
    case 2U:
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_PPD);
      cf_v2_job_take_block(&selected, donor, CF_V2_BLOCK_DOCUMENT);
      break;
    default: {
      static const cf_v2_shared_block_role_t roles[] = {
          CF_V2_BLOCK_PPD, CF_V2_BLOCK_OPTIONS, CF_V2_BLOCK_TITLE,
          CF_V2_BLOCK_DOCUMENT, CF_V2_BLOCK_CONTROL};
      size_t index;

      for (index = 0U; index < sizeof(roles) / sizeof(roles[0]); index ++)
        if (cf_v2_job_random(&random_state) & 1U)
          cf_v2_job_take_block(&selected, donor, roles[index]);
      break;
    }
  }
  output_size =
      cf_v2_pack_job_shared_blocks(out, max_out_size, &selected);
  if (output_size)
    return output_size;
  return cf_v2_pack_job_shared_blocks(out, max_out_size, base);
}
