// SPDX-License-Identifier: Apache-2.0
#include "image_raster_oracle.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_IMAGE_RASTER_MAX_OUTPUT (16U * 1024U * 1024U)
#define CF_V3_IMAGE_RASTER_MAX_PAGES 32U
#define CF_V3_IMAGE_RASTER_MAX_DIMENSION 4096U
#define CF_V3_IMAGE_RASTER_MAX_BPL (1024U * 1024U)

typedef struct cf_v3_image_raster_reader_s {
  const uint8_t *bytes;
  size_t size;
  size_t offset;
} cf_v3_image_raster_reader_t;

static bool cf_v3_image_raster_fail(const char **failure,
                                    const char *reason) {
  if (failure && !*failure) {
    *failure = reason;
  }
  return false;
}

static ssize_t cf_v3_image_raster_read(void *context, unsigned char *buffer,
                                       size_t length) {
  cf_v3_image_raster_reader_t *reader =
      (cf_v3_image_raster_reader_t *)context;

  if (!reader || reader->offset >= reader->size) {
    return 0;
  }
  if (length > reader->size - reader->offset) {
    length = reader->size - reader->offset;
  }
  memcpy(buffer, reader->bytes + reader->offset, length);
  reader->offset += length;
  return (ssize_t)length;
}

static bool cf_v3_image_raster_profile_header(
    const cups_page_header2_t *header,
    const cf_v3_image_raster_state_t *state, const char **failure) {
  size_t expected_bpl =
      cf_v3_image_raster_expected_bpl(&state->output, header->cupsWidth);

  if (!header->cupsWidth || !header->cupsHeight ||
      header->cupsWidth > CF_V3_IMAGE_RASTER_MAX_DIMENSION ||
      header->cupsHeight > CF_V3_IMAGE_RASTER_MAX_DIMENSION ||
      !expected_bpl || expected_bpl > CF_V3_IMAGE_RASTER_MAX_BPL ||
      header->cupsBitsPerColor != state->output.bits_per_color ||
      header->cupsBitsPerPixel != state->output.bits_per_pixel ||
      header->cupsBytesPerLine != expected_bpl ||
      header->cupsColorOrder != state->output.color_order ||
      header->cupsColorSpace != state->output.color_space ||
      header->cupsNumColors != state->output.num_colors ||
      header->HWResolution[0] != state->output_resolution_x ||
      header->HWResolution[1] != state->output_resolution_y) {
    fprintf(stderr,
            "image-raster-v3-header: wh=%ux%u bpc=%u/%u bpp=%u/%u "
            "bpl=%u/%zu order=%u/%u space=%u/%u colors=%u/%u "
            "dpi=%ux%u/%ux%u\n",
            header->cupsWidth, header->cupsHeight,
            header->cupsBitsPerColor, state->output.bits_per_color,
            header->cupsBitsPerPixel, state->output.bits_per_pixel,
            header->cupsBytesPerLine, expected_bpl,
            (unsigned)header->cupsColorOrder,
            (unsigned)state->output.color_order,
            (unsigned)header->cupsColorSpace,
            (unsigned)state->output.color_space, header->cupsNumColors,
            state->output.num_colors, header->HWResolution[0],
            header->HWResolution[1], state->output_resolution_x,
            state->output_resolution_y);
    return cf_v3_image_raster_fail(failure, "header-contract");
  }
  return true;
}

static bool cf_v3_image_raster_read_page(
    cups_raster_t *raster, const cups_page_header2_t *header,
    const cf_v3_image_raster_state_t *state, uint8_t **row,
    size_t *row_capacity, size_t *decoded, const char **failure) {
  size_t row_size = header->cupsBytesPerLine;
  unsigned planes = cf_v3_image_raster_plane_count(&state->output);

  if (!row_size || row_size > CF_V3_IMAGE_RASTER_MAX_BPL ||
      (uint64_t)planes * header->cupsHeight * row_size >
          CF_V3_IMAGE_RASTER_MAX_OUTPUT - *decoded) {
    return cf_v3_image_raster_fail(failure, "row-budget");
  }
  if (*row_capacity < row_size) {
    uint8_t *replacement = (uint8_t *)realloc(*row, row_size);

    if (!replacement) {
      return cf_v3_image_raster_fail(failure, "row-allocation");
    }
    *row = replacement;
    *row_capacity = row_size;
  }
  for (unsigned plane = 0U; plane < planes; plane++) {
    for (unsigned y = 0U; y < header->cupsHeight; y++) {
      if (cupsRasterReadPixels(raster, *row, (unsigned)row_size) != row_size) {
        return cf_v3_image_raster_fail(failure, "short-row");
      }
      *decoded += row_size;
    }
  }
  return true;
}

static bool cf_v3_image_raster_validate_layout(
    cups_raster_t *raster, cf_v3_image_raster_reader_t *reader,
    const cf_v3_image_raster_state_t *state, const char **failure) {
  cups_page_header2_t header;
  uint8_t *row = NULL;
  size_t row_capacity = 0U;
  size_t decoded = 0U;
  unsigned pages = 0U;
  bool valid = false;

  while (cupsRasterReadHeader2(raster, &header)) {
    if (++pages > CF_V3_IMAGE_RASTER_MAX_PAGES ||
        !cf_v3_image_raster_profile_header(&header, state, failure) ||
        !cf_v3_image_raster_read_page(raster, &header, state, &row,
                                      &row_capacity, &decoded, failure)) {
      goto cleanup;
    }
  }
  if (!pages || !decoded || reader->offset != reader->size) {
    cf_v3_image_raster_fail(failure,
                            !pages ? "empty-output" : "trailing-data");
    goto cleanup;
  }
  valid = true;

cleanup:
  free(row);
  return valid;
}

static float cf_v3_image_raster_axis_position(unsigned lower, unsigned upper,
                                              float extent, int position,
                                              bool high) {
  if (position < 0) {
    return high ? (float)lower + extent : (float)lower;
  }
  if (position > 0) {
    return high ? (float)upper : (float)upper - extent;
  }
  return ((float)upper + (float)lower + (high ? extent : -extent)) / 2.0f;
}

static void cf_v3_image_raster_position(unsigned selector, int *x, int *y) {
  static const int positions[][2] = {
      {0, 0}, {0, 1}, {-1, 1}, {1, 1}, {-1, 0},
      {1, 0}, {0, -1}, {-1, -1}, {1, -1},
  };

  *x = positions[selector % 9U][0];
  *y = positions[selector % 9U][1];
}

static void cf_v3_image_raster_natural_geometry(
    const cf_v3_image_raster_state_t *state, unsigned source_width,
    unsigned source_height, unsigned *width, unsigned *height,
    float bbox[4]) {
  float xprint = (float)source_width / 72.0f;
  float yprint = (float)source_height / 72.0f;
  float horizontal_extent;
  float vertical_extent;
  unsigned page_width = (unsigned)state->page_width;
  unsigned page_height = (unsigned)state->page_height;
  unsigned left = (unsigned)state->margin_left;
  unsigned bottom = (unsigned)state->margin_bottom;
  unsigned right = page_width - (unsigned)state->margin_right;
  unsigned top = page_height - (unsigned)state->margin_top;
  int x_position;
  int y_position;

  xprint = xprint * state->natural_scaling / 100U;
  yprint = yprint * state->natural_scaling / 100U;
  if (state->orientation & 1U) {
    horizontal_extent = yprint * 72U;
    vertical_extent = xprint * 72U;
  } else {
    horizontal_extent = xprint * 72U;
    vertical_extent = yprint * 72U;
  }
  *width = (unsigned)horizontal_extent;
  *height = (unsigned)vertical_extent;
  cf_v3_image_raster_position(state->position, &x_position, &y_position);
  if (state->orientation > 1U) {
    x_position = -x_position;
    y_position = -y_position;
  }
  bbox[0] = cf_v3_image_raster_axis_position(
      left, right, horizontal_extent, x_position, false);
  bbox[1] = cf_v3_image_raster_axis_position(
      bottom, top, vertical_extent, y_position, false);
  bbox[2] = cf_v3_image_raster_axis_position(
      left, right, horizontal_extent, x_position, true);
  bbox[3] = cf_v3_image_raster_axis_position(
      bottom, top, vertical_extent, y_position, true);
}

static void cf_v3_image_raster_natural_pixel(
    const cf_v3_image_raster_state_t *state,
    const cf_v3_image_pdf_format_result_t *image, unsigned x, unsigned y,
    uint8_t expected[3]) {
  unsigned step = 100U / state->natural_scaling;
  unsigned source_x;
  unsigned source_y;
  const uint8_t *pixel;

  switch (state->orientation) {
    default:
    case 0U:
      source_x = state->mirror ? image->width - 1U - x * step : x * step;
      source_y = y * step;
      break;
    case 1U:
      source_x = image->width - 1U - y * step;
      source_y = state->mirror ? image->height - 1U - x * step : x * step;
      break;
    case 2U:
      source_x = state->mirror ? x * step
                               : image->width - 1U - x * step;
      source_y = image->height - 1U - y * step;
      break;
    case 3U:
      source_x = y * step;
      source_y = state->mirror ? x * step
                               : image->height - 1U - x * step;
      break;
  }
  pixel = image->reference_pixels +
          ((size_t)source_y * image->width + source_x) *
              image->reference_components;
  if (image->reference_components == 1U) {
    expected[0] = (uint8_t)(255U - pixel[0]);
  } else {
    expected[0] = pixel[0];
    expected[1] = pixel[1];
    expected[2] = pixel[2];
  }
}

static bool cf_v3_image_raster_validate_natural(
    cups_raster_t *raster, cf_v3_image_raster_reader_t *reader,
    const cf_v3_image_raster_state_t *state,
    const cf_v3_image_pdf_format_result_t *image, const char **failure) {
  cups_page_header2_t header;
  uint8_t *row = NULL;
  float bbox[4];
  unsigned width;
  unsigned height;
  bool valid = false;

  cf_v3_image_raster_natural_geometry(state, image->width, image->height,
                                      &width, &height, bbox);
  if (!width || !height || !cupsRasterReadHeader2(raster, &header)) {
    cf_v3_image_raster_fail(failure, "natural-header");
    goto cleanup;
  }
  if (!cf_v3_image_raster_profile_header(&header, state, failure) ||
      header.cupsWidth != width || header.cupsHeight != height ||
      header.Orientation != state->orientation || header.Duplex ||
      header.PageSize[0] != (unsigned)state->page_width ||
      header.PageSize[1] != (unsigned)state->page_height) {
    fprintf(stderr,
            "image-raster-v3-natural-header: wh=%ux%u/%ux%u "
            "orientation=%u/%u duplex=%u page=%ux%u/%ux%u\n",
            header.cupsWidth, header.cupsHeight, width, height,
            header.Orientation, state->orientation, header.Duplex,
            header.PageSize[0], header.PageSize[1],
            (unsigned)state->page_width, (unsigned)state->page_height);
    cf_v3_image_raster_fail(failure, "natural-header");
    goto cleanup;
  }
  for (unsigned index = 0U; index < 4U; index++) {
    if (header.cupsImagingBBox[index] != bbox[index] ||
        header.ImagingBoundingBox[index] != (unsigned)bbox[index]) {
      fprintf(stderr,
              "image-raster-v3-natural-bbox: index=%u actual=%.3f/%u "
              "expected=%.3f/%u\n",
              index, header.cupsImagingBBox[index],
              header.ImagingBoundingBox[index], bbox[index],
              (unsigned)bbox[index]);
      cf_v3_image_raster_fail(failure, "natural-placement");
      goto cleanup;
    }
  }
  row = (uint8_t *)malloc(header.cupsBytesPerLine);
  if (!row) {
    cf_v3_image_raster_fail(failure, "row-allocation");
    goto cleanup;
  }
  for (unsigned y = 0U; y < height; y++) {
    if (cupsRasterReadPixels(raster, row, header.cupsBytesPerLine) !=
        header.cupsBytesPerLine) {
      cf_v3_image_raster_fail(failure, "short-row");
      goto cleanup;
    }
    for (unsigned x = 0U; x < width; x++) {
      uint8_t expected[3] = {0U, 0U, 0U};
      const uint8_t *actual =
          row + (size_t)x * image->reference_components;

      cf_v3_image_raster_natural_pixel(state, image, x, y, expected);
      if (memcmp(actual, expected, image->reference_components) != 0) {
        fprintf(stderr,
                "image-raster-v3-natural-pixel: xy=%u/%u "
                "actual=%02x/%02x/%02x expected=%02x/%02x/%02x\n",
                x, y, actual[0],
                image->reference_components > 1U ? actual[1] : 0U,
                image->reference_components > 2U ? actual[2] : 0U,
                expected[0], expected[1], expected[2]);
        cf_v3_image_raster_fail(failure, "natural-pixel");
        goto cleanup;
      }
    }
  }
  if (cupsRasterReadHeader2(raster, &header) ||
      reader->offset != reader->size) {
    cf_v3_image_raster_fail(failure, "natural-page-count");
    goto cleanup;
  }
  valid = true;

cleanup:
  free(row);
  return valid;
}

static void cf_v3_image_raster_multipage_expected(
    const cf_v3_image_raster_state_t *state, unsigned ordinal,
    uint8_t expected[3]) {
  uint8_t sentinel =
      (uint8_t)(state->phase + state->material_stride * ordinal);

  if (state->output.num_colors == 1U) {
    expected[0] = (uint8_t)(255U - sentinel);
  } else {
    static const unsigned permutations[6][3] = {
        {0U, 1U, 2U}, {0U, 2U, 1U}, {1U, 0U, 2U},
        {1U, 2U, 0U}, {2U, 0U, 1U}, {2U, 1U, 0U},
    };
    uint8_t values[3] = {
        sentinel, (uint8_t)(sentinel ^ 0x5aU),
        (uint8_t)(sentinel + 0x71U),
    };
    const unsigned *permutation = permutations[state->pattern % 6U];

    for (unsigned channel = 0U; channel < 3U; channel++) {
      expected[channel] = values[permutation[channel]];
    }
  }
}

static bool cf_v3_image_raster_validate_multipage(
    cups_raster_t *raster, cf_v3_image_raster_reader_t *reader,
    const cf_v3_image_raster_state_t *state, const char **failure) {
  cups_page_header2_t header;
  uint8_t row[63U * 3U];
  unsigned page_count = state->topology_x * state->topology_y;

  for (unsigned page = 0U; page < page_count; page++) {
    uint8_t expected[3] = {0U, 0U, 0U};
    unsigned row_size = 63U * state->output.num_colors;

    if (!cupsRasterReadHeader2(raster, &header) ||
        !cf_v3_image_raster_profile_header(&header, state, failure) ||
        header.cupsWidth != 63U || header.cupsHeight != 63U ||
        header.Orientation != state->orientation || header.Duplex) {
      return cf_v3_image_raster_fail(failure, "multipage-header");
    }
    cf_v3_image_raster_multipage_expected(state, page, expected);
    for (unsigned y = 0U; y < 63U; y++) {
      if (cupsRasterReadPixels(raster, row, row_size) != row_size) {
        return cf_v3_image_raster_fail(failure, "multipage-short-row");
      }
      for (unsigned x = 0U; x < 63U; x++) {
        const uint8_t *actual =
            row + (size_t)x * state->output.num_colors;

        if (memcmp(actual, expected, state->output.num_colors) != 0) {
          fprintf(stderr,
                  "image-raster-v3-multipage-pixel: page=%u xy=%u/%u "
                  "orientation=%u actual=%02x/%02x/%02x "
                  "expected=%02x/%02x/%02x\n",
                  page, x, y, state->orientation, actual[0],
                  state->output.num_colors > 1U ? actual[1] : 0U,
                  state->output.num_colors > 2U ? actual[2] : 0U,
                  expected[0], expected[1], expected[2]);
          return cf_v3_image_raster_fail(failure,
                                         "multipage-pixel-order");
        }
      }
    }
  }
  if (cupsRasterReadHeader2(raster, &header) ||
      reader->offset != reader->size) {
    return cf_v3_image_raster_fail(failure, "multipage-page-count");
  }
  return true;
}

static unsigned cf_v3_image_raster_bayer(unsigned size, unsigned x,
                                          unsigned y) {
  unsigned value = 0U;
  unsigned scale = 1U;

  while (size > 1U) {
    unsigned half = size / 2U;
    unsigned quadrant_x = x >= half;
    unsigned quadrant_y = y >= half;
    unsigned quadrant = !quadrant_y ? (quadrant_x ? 2U : 0U)
                                    : (quadrant_x ? 1U : 3U);

    value += scale * quadrant;
    scale *= 4U;
    x %= half;
    y %= half;
    size = half;
  }
  return value;
}

static void cf_v3_image_raster_rgb_to_cmy(const uint8_t rgb[3],
                                          uint8_t cmy[3]) {
  int c = 255 - rgb[0];
  int m = 255 - rgb[1];
  int y = 255 - rgb[2];
  int k = c < m ? c : m;

  if (y < k) {
    k = y;
  }
  cmy[0] = (uint8_t)(((255 - rgb[1] / 4) * (c - k)) / 255 + k);
  cmy[1] = (uint8_t)(((255 - rgb[2] / 4) * (m - k)) / 255 + k);
  cmy[2] = (uint8_t)(((255 - rgb[0] / 4) * (y - k)) / 255 + k);
}

static unsigned cf_v3_image_raster_quantize(uint8_t value, unsigned bits,
                                             unsigned threshold) {
  if (bits == 1U) {
    return value > threshold;
  }
  if (bits == 2U) {
    unsigned level;

    if (value == 0U) {
      return 0U;
    }
    if (value == 255U) {
      return 3U;
    }
    level = (value & 63U) > threshold ? value / 85U + 1U
                                      : value / 64U;
    return level > 3U ? 3U : level;
  }
  if (value == 0U) {
    return 0U;
  }
  if (value == 255U) {
    return 15U;
  }
  if ((value & 15U) > threshold) {
    unsigned level = value / 17U + 1U;
    return level > 15U ? 15U : level;
  }
  return value / 16U;
}

static void cf_v3_image_raster_append_bits(uint8_t *row, size_t row_size,
                                           size_t *bit_offset,
                                           unsigned value, unsigned width) {
  for (unsigned bit = width; bit > 0U; bit--) {
    size_t byte = *bit_offset / 8U;
    unsigned shift = 7U - (unsigned)(*bit_offset & 7U);

    if (byte < row_size) {
      row[byte] |=
          (uint8_t)(((value >> (bit - 1U)) & 1U) << shift);
    }
    (*bit_offset)++;
  }
}

static void cf_v3_image_raster_cmy_row(
    const cf_v3_image_raster_state_t *state,
    const cf_v3_image_pdf_format_result_t *image, unsigned output_y,
    uint8_t *expected, size_t expected_size) {
  unsigned bits = state->output.bits_per_color;
  unsigned period = bits == 1U ? 16U : bits == 2U ? 8U : 4U;
  unsigned source_y = output_y;
  size_t bit_offset = 0U;

  if (state->cmy_relation_stage >= 2U &&
      source_y + 1U < state->explicit_height) {
    source_y++;
  }
  memset(expected, 0, expected_size);
  for (unsigned x = 0U; x < state->explicit_width; x++) {
    const uint8_t *rgb = image->reference_pixels +
        ((size_t)source_y * state->explicit_width + x) * 3U;
    uint8_t cmy[3];
    unsigned quantized[3];
    unsigned threshold = cf_v3_image_raster_bayer(
        period, (state->explicit_width - x) & (period - 1U),
        (state->explicit_height - output_y) & (period - 1U));

    cf_v3_image_raster_rgb_to_cmy(rgb, cmy);
    for (unsigned channel = 0U; channel < 3U; channel++) {
      quantized[channel] =
          cf_v3_image_raster_quantize(cmy[channel], bits, threshold);
    }
    if (state->cmy_relation_stage == 0U) {
      for (unsigned channel = 0U; channel < 3U; channel++) {
        cf_v3_image_raster_append_bits(expected, expected_size, &bit_offset,
                                       quantized[channel], bits);
      }
    } else if (bits == 1U) {
      unsigned shift = (x & 1U) ? 0U : 4U;
      uint8_t nibble =
          (uint8_t)((quantized[0] << 2U) | (quantized[1] << 1U) |
                    quantized[2]);
      if (x / 2U < expected_size) {
        expected[x / 2U] |= (uint8_t)(nibble << shift);
      }
    } else if (bits == 2U) {
      if (x < expected_size) {
        expected[x] = (uint8_t)((quantized[0] << 4U) |
                                (quantized[1] << 2U) | quantized[2]);
      }
    } else {
      if ((size_t)x * 2U < expected_size) {
        expected[(size_t)x * 2U] = (uint8_t)quantized[0];
      }
      if ((size_t)x * 2U + 1U < expected_size) {
        expected[(size_t)x * 2U + 1U] =
            (uint8_t)((quantized[1] << 4U) | quantized[2]);
      }
    }
  }
}

static bool cf_v3_image_raster_validate_cmy(
    cups_raster_t *raster, cf_v3_image_raster_reader_t *reader,
    const cf_v3_image_raster_state_t *state,
    const cf_v3_image_pdf_format_result_t *image, const char **failure) {
  cups_page_header2_t header;
  uint8_t *actual = NULL;
  uint8_t *expected = NULL;
  bool valid = false;

  if (!cupsRasterReadHeader2(raster, &header) ||
      !cf_v3_image_raster_profile_header(&header, state, failure) ||
      header.cupsWidth != state->explicit_width ||
      header.cupsHeight != state->explicit_height ||
      header.Orientation != 0U || header.Duplex) {
    cf_v3_image_raster_fail(failure, "cmy-header");
    goto cleanup;
  }
  actual = (uint8_t *)malloc(header.cupsBytesPerLine);
  expected = (uint8_t *)malloc(header.cupsBytesPerLine);
  if (!actual || !expected) {
    cf_v3_image_raster_fail(failure, "row-allocation");
    goto cleanup;
  }
  for (unsigned y = 0U; y < state->explicit_height; y++) {
    if (cupsRasterReadPixels(raster, actual, header.cupsBytesPerLine) !=
        header.cupsBytesPerLine) {
      cf_v3_image_raster_fail(failure, "cmy-short-row");
      goto cleanup;
    }
    cf_v3_image_raster_cmy_row(state, image, y, expected,
                               header.cupsBytesPerLine);
    if (memcmp(actual, expected, header.cupsBytesPerLine) != 0) {
      size_t offset = 0U;
      while (offset < header.cupsBytesPerLine &&
             actual[offset] == expected[offset]) {
        offset++;
      }
      fprintf(stderr,
              "image-raster-v3-cmy-row: y=%u byte=%zu/%u "
              "actual=%02x expected=%02x bits=%u geometry=%ux%u stage=%u\n",
              y, offset, header.cupsBytesPerLine,
              offset < header.cupsBytesPerLine ? actual[offset] : 0U,
              offset < header.cupsBytesPerLine ? expected[offset] : 0U,
              state->output.bits_per_color, state->explicit_width,
              state->explicit_height, state->cmy_relation_stage);
      cf_v3_image_raster_fail(failure, "cmy-dither-or-packing");
      goto cleanup;
    }
  }
  if (cupsRasterReadHeader2(raster, &header) ||
      reader->offset != reader->size) {
    cf_v3_image_raster_fail(failure, "cmy-page-count");
    goto cleanup;
  }
  valid = true;

cleanup:
  free(expected);
  free(actual);
  return valid;
}

bool cf_v3_image_raster_validate(
    const uint8_t *output, size_t output_size,
    const cf_v3_image_raster_state_t *state,
    const cf_v3_image_pdf_format_result_t *image, const char **failure) {
  cf_v3_image_raster_reader_t reader = {output, output_size, 0U};
  cups_raster_t *raster;
  bool valid;

  if (!output || !output_size || output_size > CF_V3_IMAGE_RASTER_MAX_OUTPUT ||
      !state || !image ||
      !(raster = cupsRasterOpenIO(cf_v3_image_raster_read, &reader,
                                 CUPS_RASTER_READ))) {
    return cf_v3_image_raster_fail(failure, "raster-open-or-bounds");
  }
  if (state->profile == CF_V3_IMAGE_RASTER_NATURAL) {
    valid = cf_v3_image_raster_validate_natural(
        raster, &reader, state, image, failure);
  } else if (state->profile == CF_V3_IMAGE_RASTER_MULTIPAGE) {
    valid = cf_v3_image_raster_validate_multipage(
        raster, &reader, state, failure);
  } else if (state->profile == CF_V3_IMAGE_RASTER_CMY) {
    valid = cf_v3_image_raster_validate_cmy(
        raster, &reader, state, image, failure);
  } else {
    valid = cf_v3_image_raster_validate_layout(raster, &reader, state,
                                               failure);
  }
  cupsRasterClose(raster);
  return valid;
}
