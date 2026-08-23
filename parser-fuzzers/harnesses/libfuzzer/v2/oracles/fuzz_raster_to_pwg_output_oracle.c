// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * Total-mapped CUPS Raster -> PWG/Apple Raster output oracle.
 *
 * Bytes 0..11 select a finite page program. Remaining bytes (up to 256) are
 * cyclic pixel material. Missing selectors and material map to deterministic
 * defaults, so every libFuzzer input reaches the real filter route.
 */

#include "../include/control.h"
#include "../include/direct_route.h"

#include <cups/raster.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V2_RPWG_SELECTOR_SIZE 12U
#define CF_V2_RPWG_MAX_MATERIAL 256U
#define CF_V2_RPWG_MAX_PAGES 4U
#define CF_V2_RPWG_MAX_ROW_BYTES 1152U

typedef struct cf_v2_rpwg_profile_s {
  cups_cspace_t color_space;
  unsigned colors;
  unsigned bits_per_color;
} cf_v2_rpwg_profile_t;

typedef struct cf_v2_rpwg_page_s {
  const cf_v2_rpwg_profile_t *profile;
  unsigned width;
  unsigned height;
  unsigned left;
  unsigned right;
  unsigned top;
  unsigned bottom;
  unsigned input_bytes_per_line;
  unsigned output_bytes_per_line;
} cf_v2_rpwg_page_t;

#ifdef CF_V2_RPWG_APPLE
static const cf_v2_rpwg_profile_t cf_v2_rpwg_profiles[] = {
    {CUPS_CSPACE_W, 1U, 1U},
    {CUPS_CSPACE_W, 1U, 8U},
    {CUPS_CSPACE_RGB, 3U, 8U},
    {CUPS_CSPACE_SRGB, 3U, 8U},
    {CUPS_CSPACE_ADOBERGB, 3U, 8U},
    {CUPS_CSPACE_CMYK, 4U, 8U},
    {CUPS_CSPACE_RGB, 3U, 16U},
    {CUPS_CSPACE_CMYK, 4U, 16U},
};
#else
static const cf_v2_rpwg_profile_t cf_v2_rpwg_profiles[] = {
    {CUPS_CSPACE_K, 1U, 1U},
    {CUPS_CSPACE_K, 1U, 8U},
    {CUPS_CSPACE_W, 1U, 8U},
    {CUPS_CSPACE_RGB, 3U, 8U},
    {CUPS_CSPACE_SRGB, 3U, 8U},
    {CUPS_CSPACE_ADOBERGB, 3U, 8U},
    {CUPS_CSPACE_CMYK, 4U, 8U},
    {CUPS_CSPACE_RGB, 3U, 16U},
    {CUPS_CSPACE_CMYK, 4U, 16U},
};
#endif

static const unsigned cf_v2_rpwg_widths[] = {
    8U, 16U, 24U, 32U, 40U, 64U, 72U, 128U,
};
static const unsigned cf_v2_rpwg_heights[] = {1U, 2U, 3U, 4U, 8U, 16U};
static const unsigned cf_v2_rpwg_margins[] = {0U, 1U, 2U, 4U, 8U};
static const unsigned cf_v2_rpwg_profile_strides[] = {0U, 1U, 2U, 3U, 5U};

static uint8_t cf_v2_rpwg_selector(const uint8_t *data, size_t size,
                                   size_t index) {
  return index < size ? data[index] : 0U;
}

static unsigned cf_v2_rpwg_white(const cf_v2_rpwg_profile_t *profile) {
  switch (profile->color_space) {
    case CUPS_CSPACE_W:
    case CUPS_CSPACE_RGB:
    case CUPS_CSPACE_SRGB:
    case CUPS_CSPACE_ADOBERGB:
      return 0xffU;
    default:
      return 0U;
  }
}

static uint8_t cf_v2_rpwg_material(const uint8_t *material,
                                   size_t material_size, unsigned pattern,
                                   unsigned page, unsigned row, size_t offset) {
  uint8_t value = material_size
                      ? material[((size_t)page * 1031U +
                                  (size_t)row * 257U + offset * 17U) %
                                 material_size]
                      : (uint8_t)(0x21U + page * 37U + row * 19U +
                                  (unsigned)offset * 13U);

  switch (pattern % 7U) {
    case 0U:
      return value;
    case 1U:
      return 0x00U;
    case 2U:
      return 0xffU;
    case 3U:
      return ((offset + row + page) & 1U) ? 0xaaU : 0x55U;
    case 4U:
      return (uint8_t)(offset * 31U + row * 17U + page * 7U);
    case 5U:
      return (uint8_t)(value ^ (uint8_t)(page * 0x31U + row));
    default:
      return (uint8_t)(1U << (offset & 7U));
  }
}

static void cf_v2_rpwg_page_state(const uint8_t selector[12], unsigned page,
                                  cf_v2_rpwg_page_t *state) {
  const size_t profile_count =
      sizeof(cf_v2_rpwg_profiles) / sizeof(cf_v2_rpwg_profiles[0]);
  const unsigned stride = cf_v2_rpwg_profile_strides[
      selector[9] % (sizeof(cf_v2_rpwg_profile_strides) /
                     sizeof(cf_v2_rpwg_profile_strides[0]))];
  const unsigned profile_index =
      (selector[0] + page * stride) % (unsigned)profile_count;
  unsigned margin_scale;
  unsigned bits_per_pixel;

  memset(state, 0, sizeof(*state));
  state->profile = &cf_v2_rpwg_profiles[profile_index];
  state->width = cf_v2_rpwg_widths[
      (selector[1] + page * (1U + (selector[11] & 1U))) %
      (sizeof(cf_v2_rpwg_widths) / sizeof(cf_v2_rpwg_widths[0]))];
  state->height = cf_v2_rpwg_heights[
      (selector[2] + page * ((selector[11] >> 1U) & 1U)) %
      (sizeof(cf_v2_rpwg_heights) / sizeof(cf_v2_rpwg_heights[0]))];
  margin_scale = state->profile->bits_per_color == 1U ? 8U : 1U;
  state->left = margin_scale * cf_v2_rpwg_margins[
      (selector[3] + page) %
      (sizeof(cf_v2_rpwg_margins) / sizeof(cf_v2_rpwg_margins[0]))];
  state->right = margin_scale * cf_v2_rpwg_margins[
      (selector[4] + page * 2U) %
      (sizeof(cf_v2_rpwg_margins) / sizeof(cf_v2_rpwg_margins[0]))];
  state->top = cf_v2_rpwg_margins[
      (selector[5] + page * 3U) %
      (sizeof(cf_v2_rpwg_margins) / sizeof(cf_v2_rpwg_margins[0]))];
  state->bottom = cf_v2_rpwg_margins[
      (selector[6] + page * 4U) %
      (sizeof(cf_v2_rpwg_margins) / sizeof(cf_v2_rpwg_margins[0]))];
  bits_per_pixel = state->profile->colors * state->profile->bits_per_color;
  state->input_bytes_per_line = state->width * bits_per_pixel / 8U;
  state->output_bytes_per_line =
      (state->width + state->left + state->right) * bits_per_pixel / 8U;
}

static uint8_t *cf_v2_rpwg_document(const uint8_t selector[12],
                                    const uint8_t *material,
                                    size_t material_size,
                                    cf_v2_rpwg_page_t pages[4],
                                    unsigned page_count,
                                    size_t *document_size) {
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;

  for (unsigned page = 0U; page < page_count; page++) {
    cf_v2_rpwg_page_state(selector, page, &pages[page]);
    total += sizeof(cups_page_header2_t) +
             (size_t)pages[page].height * pages[page].input_bytes_per_line;
  }
  document = (uint8_t *)malloc(total);
  if (!document) {
    return NULL;
  }
  memcpy(document, "3SaR", 4U);
  for (unsigned page = 0U; page < page_count; page++) {
    const cf_v2_rpwg_page_t *state = &pages[page];
    cups_page_header2_t header;
    const unsigned bits_per_pixel =
        state->profile->colors * state->profile->bits_per_color;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "stationery", sizeof("stationery"));
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = state->width + state->left + state->right;
    header.PageSize[1] = state->height + state->top + state->bottom;
    header.ImagingBoundingBox[0] = state->left;
    header.ImagingBoundingBox[1] = state->bottom;
    header.ImagingBoundingBox[2] = state->left + state->width;
    header.ImagingBoundingBox[3] = state->bottom + state->height;
    header.cupsPageSize[0] = (float)header.PageSize[0];
    header.cupsPageSize[1] = (float)header.PageSize[1];
    header.cupsImagingBBox[0] = (float)header.ImagingBoundingBox[0];
    header.cupsImagingBBox[1] = (float)header.ImagingBoundingBox[1];
    header.cupsImagingBBox[2] = (float)header.ImagingBoundingBox[2];
    header.cupsImagingBBox[3] = (float)header.ImagingBoundingBox[3];
    header.cupsWidth = state->width;
    header.cupsHeight = state->height;
    header.cupsBitsPerColor = state->profile->bits_per_color;
    header.cupsBitsPerPixel = bits_per_pixel;
    header.cupsBytesPerLine = state->input_bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = state->profile->color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = state->profile->colors;
    header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] = page_count;
    header.NumCopies = 1U;
    header.Duplex = (selector[10] >> (page & 3U)) & 1U;
    header.Tumble = (selector[10] >> (4U + (page & 3U))) & 1U;
    header.Orientation = (cups_orient_t)((selector[11] + page) % 4U);
    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);
    for (unsigned row = 0U; row < state->height; row++) {
      for (unsigned column = 0U; column < state->input_bytes_per_line;
           column++) {
        document[offset++] = cf_v2_rpwg_material(
            material, material_size, selector[8], page, row, column);
      }
    }
  }
  *document_size = total;
  return document;
}

static void cf_v2_rpwg_expected_row(uint8_t *row,
                                    const cf_v2_rpwg_page_t *state,
                                    const uint8_t selector[12],
                                    const uint8_t *material,
                                    size_t material_size, unsigned page,
                                    unsigned output_row) {
  const unsigned top_end = state->top;
  const unsigned content_end = top_end + state->height;
  const unsigned left_bytes =
      state->left * state->profile->colors * state->profile->bits_per_color /
      8U;

  memset(row, (int)cf_v2_rpwg_white(state->profile),
         state->output_bytes_per_line);
  if (output_row >= top_end && output_row < content_end) {
    const unsigned source_row = output_row - top_end;
    for (unsigned column = 0U; column < state->input_bytes_per_line;
         column++) {
      row[left_bytes + column] = cf_v2_rpwg_material(
          material, material_size, selector[8], page, source_row, column);
    }
  }
}

static int cf_v2_rpwg_check_output(const cf_v2_run_result_t *result,
                                   const uint8_t selector[12],
                                   const uint8_t *material,
                                   size_t material_size,
                                   const cf_v2_rpwg_page_t pages[4],
                                   unsigned page_count,
                                   const char **failure) {
  uint8_t actual[CF_V2_RPWG_MAX_ROW_BYTES];
  uint8_t expected[CF_V2_RPWG_MAX_ROW_BYTES];
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  FILE *file = NULL;
  int fd = -1;
  int valid = 0;

  if (!result->captured || result->status != 0 || !result->output ||
      !result->output_size) {
    *failure = "route-output";
    goto done;
  }
  file = tmpfile();
  if (!file || fwrite(result->output, 1U, result->output_size, file) !=
                   result->output_size ||
      fflush(file) != 0 || fseek(file, 0, SEEK_SET) != 0 ||
      (fd = dup(fileno(file))) < 0 ||
      !(raster = cupsRasterOpen(fd, CUPS_RASTER_READ))) {
    *failure = "reader-open";
    goto done;
  }
  for (unsigned page = 0U; page < page_count; page++) {
    const cf_v2_rpwg_page_t *state = &pages[page];
    const unsigned outer_width = state->width + state->left + state->right;
    const unsigned outer_height = state->height + state->top + state->bottom;
    const unsigned bits_per_pixel =
        state->profile->colors * state->profile->bits_per_color;

    if (!cupsRasterReadHeader2(raster, &header)) {
      *failure = "page-count-short";
      goto done;
    }
    if (header.cupsWidth != outer_width || header.cupsHeight != outer_height ||
        header.cupsBitsPerColor != state->profile->bits_per_color ||
        header.cupsBitsPerPixel != bits_per_pixel ||
        header.cupsBytesPerLine != state->output_bytes_per_line ||
        header.cupsColorOrder != CUPS_ORDER_CHUNKED ||
        header.cupsColorSpace != state->profile->color_space ||
        header.cupsNumColors != state->profile->colors ||
        header.HWResolution[0] != 72U || header.HWResolution[1] != 72U) {
      *failure = "header-contract";
      goto done;
    }
#ifndef CF_V2_RPWG_APPLE
    if (header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] != page_count) {
      *failure = "page-count-header";
      goto done;
    }
    if (header.ImagingBoundingBox[0] != state->left ||
        header.ImagingBoundingBox[1] != state->bottom ||
        header.ImagingBoundingBox[2] != state->left + state->width ||
        header.ImagingBoundingBox[3] != state->bottom + state->height ||
        header.cupsInteger[CUPS_RASTER_PWG_ImageBoxLeft] != state->left ||
        header.cupsInteger[CUPS_RASTER_PWG_ImageBoxTop] != state->bottom ||
        header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] !=
            state->left + state->width ||
        header.cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] !=
            state->bottom + state->height) {
      *failure = "margin-header";
      goto done;
    }
#endif
    if (state->output_bytes_per_line > sizeof(actual)) {
      *failure = "row-bound";
      goto done;
    }
    for (unsigned row = 0U; row < outer_height; row++) {
      if (cupsRasterReadPixels(raster, actual,
                               state->output_bytes_per_line) !=
          state->output_bytes_per_line) {
        *failure = "short-row";
        goto done;
      }
      cf_v2_rpwg_expected_row(expected, state, selector, material,
                              material_size, page, row);
      if (memcmp(actual, expected, state->output_bytes_per_line) != 0) {
        *failure = row < state->top || row >= state->top + state->height
                       ? "vertical-padding"
                       : "horizontal-padding-or-pixel";
        goto done;
      }
    }
  }
  if (cupsRasterReadHeader2(raster, &header)) {
    *failure = "page-count-long";
    goto done;
  }
  valid = 1;

done:
  if (raster) {
    cupsRasterClose(raster);
  }
  if (fd >= 0) {
    close(fd);
  }
  if (file) {
    fclose(file);
  }
  return valid;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t selector[CF_V2_RPWG_SELECTOR_SIZE];
  const uint8_t *material = NULL;
  size_t material_size = 0U;
  cf_v2_rpwg_page_t pages[CF_V2_RPWG_MAX_PAGES];
  unsigned page_count;
  size_t document_size = 0U;
  uint8_t *document;
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  const char *failure = NULL;
  int executed;

  for (size_t index = 0U; index < sizeof(selector); index++) {
    selector[index] = cf_v2_rpwg_selector(data, size, index);
  }
  if (data && size > sizeof(selector)) {
    material = data + sizeof(selector);
    material_size = size - sizeof(selector);
    if (material_size > CF_V2_RPWG_MAX_MATERIAL) {
      material_size = CF_V2_RPWG_MAX_MATERIAL;
    }
  }
  page_count = 1U + selector[7] % CF_V2_RPWG_MAX_PAGES;
  document = cf_v2_rpwg_document(selector, material, material_size, pages,
                                 page_count, &document_size);
  if (!document) {
    return 0;
  }
  memset(&control, 0, sizeof(control));
  control.copies = 0U;
  control.sides = 0U;
  control.quality = selector[10];
  control.media_type = selector[11];
  executed = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &result);
  if (!executed ||
      !cf_v2_rpwg_check_output(&result, selector, material, material_size,
                               pages, page_count, &failure)) {
    fprintf(stderr, "%s: %s\n", CF_V2_TARGET_NAME,
            failure ? failure : "route-not-executed");
    cf_v2_free_run_result(&result);
    free(document);
    __builtin_trap();
  }
  cf_v2_free_run_result(&result);
  free(document);
  return 0;
}
