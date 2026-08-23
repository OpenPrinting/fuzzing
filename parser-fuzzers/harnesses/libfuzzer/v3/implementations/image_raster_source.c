// SPDX-License-Identifier: Apache-2.0
#include "image_raster_source.h"

#include <png.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_IMAGE_RASTER_SPECIAL_MAX_ENCODED (2U * 1024U * 1024U)
#define CF_V3_IMAGE_RASTER_SPECIAL_MAX_PIXELS (2U * 1024U * 1024U)

typedef struct cf_v3_image_raster_buffer_s {
  uint8_t *bytes;
  size_t size;
  size_t capacity;
  int failed;
} cf_v3_image_raster_buffer_t;

static void cf_v3_image_raster_png_error(png_structp png,
                                         png_const_charp message) {
  (void)message;
  longjmp(png_jmpbuf(png), 1);
}

static void cf_v3_image_raster_png_warning(png_structp png,
                                           png_const_charp message) {
  (void)png;
  (void)message;
}

static void cf_v3_image_raster_png_write(png_structp png, png_bytep bytes,
                                         png_size_t size) {
  cf_v3_image_raster_buffer_t *buffer =
      (cf_v3_image_raster_buffer_t *)png_get_io_ptr(png);
  size_t required;
  size_t capacity;
  uint8_t *replacement;

  if (!buffer || size > SIZE_MAX - buffer->size) {
    png_error(png, "image-raster PNG size overflow");
  }
  required = buffer->size + size;
  if (required > CF_V3_IMAGE_RASTER_SPECIAL_MAX_ENCODED) {
    png_error(png, "image-raster PNG budget exceeded");
  }
  if (required > buffer->capacity) {
    capacity = buffer->capacity ? buffer->capacity : 4096U;
    while (capacity < required) {
      if (capacity > CF_V3_IMAGE_RASTER_SPECIAL_MAX_ENCODED / 2U) {
        capacity = CF_V3_IMAGE_RASTER_SPECIAL_MAX_ENCODED;
        break;
      }
      capacity *= 2U;
    }
    replacement = (uint8_t *)realloc(buffer->bytes, capacity);
    if (!replacement) {
      buffer->failed = 1;
      png_error(png, "image-raster PNG allocation failed");
    }
    buffer->bytes = replacement;
    buffer->capacity = capacity;
  }
  memcpy(buffer->bytes + buffer->size, bytes, size);
  buffer->size = required;
}

static void cf_v3_image_raster_png_flush(png_structp png) { (void)png; }

static int cf_v3_image_raster_encode_png(
    const uint8_t *pixels, unsigned width, unsigned height,
    unsigned components, unsigned xppi, unsigned yppi,
    cf_v3_image_pdf_format_result_t *result) {
  cf_v3_image_raster_buffer_t buffer;
  png_structp png = NULL;
  png_infop info = NULL;
  png_bytep *rows = NULL;
  int color_type;
  int success = 0;

  if (!pixels || !width || !height ||
      (components != 1U && components != 3U)) {
    return -1;
  }
  memset(&buffer, 0, sizeof(buffer));
  rows = (png_bytep *)malloc((size_t)height * sizeof(*rows));
  if (!rows) {
    return -1;
  }
  for (unsigned y = 0U; y < height; y++) {
    rows[y] = (png_bytep)(pixels + (size_t)y * width * components);
  }
  png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL,
                                cf_v3_image_raster_png_error,
                                cf_v3_image_raster_png_warning);
  if (!png || !(info = png_create_info_struct(png))) {
    goto cleanup;
  }
  if (setjmp(png_jmpbuf(png))) {
    goto cleanup;
  }
  color_type = components == 1U ? PNG_COLOR_TYPE_GRAY : PNG_COLOR_TYPE_RGB;
  png_set_write_fn(png, &buffer, cf_v3_image_raster_png_write,
                   cf_v3_image_raster_png_flush);
  png_set_compression_level(png, 6);
  png_set_IHDR(png, info, width, height, 8, color_type,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE,
               PNG_FILTER_TYPE_BASE);
  png_set_pHYs(png, info,
               (png_uint_32)(((uint64_t)xppi * 10000U + 127U) / 254U),
               (png_uint_32)(((uint64_t)yppi * 10000U + 127U) / 254U),
               PNG_RESOLUTION_METER);
  png_write_info(png, info);
  png_write_image(png, rows);
  png_write_end(png, info);
  if (!buffer.failed && buffer.size) {
    result->encoded_bytes = buffer.bytes;
    buffer.bytes = NULL;
    result->encoded_size = buffer.size;
    result->mime = "image/png";
    result->format = CF_V3_IMAGE_PDF_FORMAT_PNG;
    success = 1;
  }

cleanup:
  if (png) {
    png_destroy_write_struct(&png, info ? &info : NULL);
  }
  free(rows);
  free(buffer.bytes);
  return success ? 0 : -1;
}

static uint8_t cf_v3_image_raster_material(const uint8_t *material,
                                           size_t material_size,
                                           size_t index) {
  if (material && material_size) {
    return material[index % material_size];
  }
  return (uint8_t)(index * 131U + index / 17U);
}

static void cf_v3_image_raster_rgb_permutation(unsigned selector,
                                               unsigned output[3]) {
  static const unsigned permutations[6][3] = {
      {0U, 1U, 2U}, {0U, 2U, 1U}, {1U, 0U, 2U},
      {1U, 2U, 0U}, {2U, 0U, 1U}, {2U, 1U, 0U},
  };

  memcpy(output, permutations[selector % 6U], sizeof(permutations[0]));
}

static int cf_v3_image_raster_build_multipage(
    const cf_v3_image_raster_state_t *state, const uint8_t *material,
    size_t material_size, cf_v3_image_pdf_format_result_t *result) {
  size_t size = (size_t)state->explicit_width * state->explicit_height *
                state->output.num_colors;
  uint8_t *pixels;
  bool sentinels[256] = {false};
  unsigned permutation[3];
  unsigned ordinal = 0U;

  if (!size || size > CF_V3_IMAGE_RASTER_SPECIAL_MAX_PIXELS ||
      !(pixels = (uint8_t *)malloc(size))) {
    return -1;
  }
  memset(pixels, 0, size);
  cf_v3_image_raster_rgb_permutation(state->pattern, permutation);
  for (unsigned page_x = 0U; page_x < state->topology_x; page_x++) {
    for (unsigned page_y = 0U; page_y < state->topology_y; page_y++) {
      uint64_t x0;
      uint64_t x1;
      uint64_t y0;
      uint64_t y1;
      uint8_t sentinel =
          (uint8_t)(state->phase + state->material_stride * ordinal);

      if (sentinels[sentinel]) {
        free(pixels);
        return -1;
      }
      sentinels[sentinel] = true;
      if (state->orientation & 1U) {
        x0 = (uint64_t)state->explicit_width * page_y /
             state->topology_y;
        x1 = (uint64_t)state->explicit_width * (page_y + 1U) /
             state->topology_y;
        y0 = (uint64_t)state->explicit_height * page_x /
             state->topology_x;
        y1 = (uint64_t)state->explicit_height * (page_x + 1U) /
             state->topology_x;
      } else {
        x0 = (uint64_t)state->explicit_width * page_x /
             state->topology_x;
        x1 = (uint64_t)state->explicit_width * (page_x + 1U) /
             state->topology_x;
        y0 = (uint64_t)state->explicit_height * page_y /
             state->topology_y;
        y1 = (uint64_t)state->explicit_height * (page_y + 1U) /
             state->topology_y;
      }
      for (uint64_t y = y0; y < y1; y++) {
        for (uint64_t x = x0; x < x1; x++) {
          uint8_t *pixel = pixels +
              ((size_t)y * state->explicit_width + (size_t)x) *
                  state->output.num_colors;

          if (state->output.num_colors == 1U) {
            pixel[0] = sentinel;
          } else {
            uint8_t values[3] = {
                sentinel, (uint8_t)(sentinel ^ 0x5aU),
                (uint8_t)(sentinel + 0x71U),
            };
            for (unsigned channel = 0U; channel < 3U; channel++) {
              pixel[channel] = values[permutation[channel]];
            }
          }
        }
      }
      ordinal++;
    }
  }
  if (material_size) {
    /* Keep the material block visible to coverage without destroying the
     * per-page sentinels used by the output oracle. */
    pixels[size - 1U] ^= cf_v3_image_raster_material(
        material, material_size, state->phase);
    pixels[size - 1U] ^= cf_v3_image_raster_material(
        material, material_size, state->phase);
  }
  result->reference_pixels = pixels;
  result->reference_size = size;
  result->reference_components = (uint8_t)state->output.num_colors;
  result->reference_colorspace = state->output.num_colors == 1U
                                     ? CF_V3_IMAGE_PDF_COLORSPACE_GRAY
                                     : CF_V3_IMAGE_PDF_COLORSPACE_RGB;
  result->width = (uint16_t)state->explicit_width;
  result->height = (uint16_t)state->explicit_height;
  result->xppi = (uint16_t)state->xppi;
  result->yppi = (uint16_t)state->yppi;
  if (cf_v3_image_raster_encode_png(
          pixels, state->explicit_width, state->explicit_height,
          state->output.num_colors, state->xppi, state->yppi, result) != 0) {
    free(pixels);
    memset(result, 0, sizeof(*result));
    return -1;
  }
  return 0;
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

static unsigned cf_v3_image_raster_cmy_period(unsigned bits) {
  return bits == 1U ? 16U : bits == 2U ? 8U : 4U;
}

static uint8_t cf_v3_image_raster_clamp(int value) {
  return value < 0 ? 0U : value > 255 ? 255U : (uint8_t)value;
}

static void cf_v3_image_raster_cmy_source_pixel(
    const cf_v3_image_raster_state_t *state, unsigned x, unsigned y,
    const uint8_t *material, size_t material_size, uint8_t rgb[3]) {
  static const uint8_t boundaries[] = {
      0U, 1U, 15U, 16U, 17U, 63U, 64U, 65U, 84U, 85U,
      86U, 127U, 128U, 169U, 170U, 191U, 192U, 254U, 255U,
  };
  static const uint8_t bases[][3] = {
      {0x11U, 0x70U, 0xd1U}, {0x20U, 0x81U, 0xe2U},
      {0x31U, 0x92U, 0xf3U}, {0x42U, 0xa3U, 0xc4U},
  };
  unsigned permutation[3];
  unsigned period =
      cf_v3_image_raster_cmy_period(state->output.bits_per_color);
  unsigned threshold = cf_v3_image_raster_bayer(
      period, (state->explicit_width - x) & (period - 1U),
      (state->explicit_height - y) & (period - 1U));

  cf_v3_image_raster_rgb_permutation(state->material_stride, permutation);
  switch (state->pattern % 9U) {
    case 0U: {
      uint8_t value = boundaries[(x + y * 3U + state->phase) %
                                 (sizeof(boundaries) /
                                  sizeof(boundaries[0]))];
      rgb[0] = rgb[1] = rgb[2] = (uint8_t)(255U - value);
      break;
    }
    case 1U: {
      uint8_t value = cf_v3_image_raster_clamp(
          (int)threshold + state->cmy_threshold_delta);
      rgb[0] = rgb[1] = rgb[2] = (uint8_t)(255U - value);
      break;
    }
    case 2U: {
      uint8_t value = boundaries[(x * 5U + y * 7U + state->phase) %
                                 (sizeof(boundaries) /
                                  sizeof(boundaries[0]))];
      rgb[0] = rgb[1] = rgb[2] = (uint8_t)(255U - value);
      if (((x ^ y) & 1U) != 0U) {
        rgb[permutation[(x + y) % 3U]] ^= 0x3fU;
      }
      break;
    }
    case 3U:
      for (unsigned channel = 0U; channel < 3U; channel++) {
        uint8_t value = bases[(x + y + state->phase) % 4U]
                             [permutation[channel]];
        rgb[channel] = (uint8_t)(255U - value);
      }
      break;
    case 4U:
      for (unsigned channel = 0U; channel < 3U; channel++) {
        rgb[channel] = (uint8_t)(x * (17U + 6U * channel) +
                                 y * (29U + 4U * channel) +
                                 state->phase * 11U + channel * 0x41U);
      }
      break;
    case 5U: {
      uint8_t value = ((x ^ y ^ state->phase) & 1U) ? 0U : 255U;
      rgb[0] = value;
      rgb[1] = (uint8_t)(255U - value);
      rgb[2] = ((x + y) & 1U) ? value : (uint8_t)(255U - value);
      break;
    }
    case 6U:
      rgb[0] = (uint8_t)(x * 255U / state->explicit_width);
      rgb[1] = (uint8_t)(y * 255U / state->explicit_height);
      rgb[2] = (uint8_t)((x + y + state->phase) * 37U);
      break;
    case 7U:
      rgb[0] = rgb[1] = rgb[2] = 255U;
      rgb[permutation[(x + y + state->phase) % 3U]] =
          boundaries[(x + y + state->phase) %
                     (sizeof(boundaries) / sizeof(boundaries[0]))];
      break;
    default:
      for (unsigned channel = 0U; channel < 3U; channel++) {
        uint8_t target = cf_v3_image_raster_clamp(
            (int)threshold + state->cmy_threshold_delta +
            (int)permutation[channel] - 1);
        rgb[channel] = (uint8_t)(255U - target);
      }
      if (material_size) {
        rgb[(x + y) % 3U] ^= cf_v3_image_raster_material(
            material, material_size, (size_t)y * state->explicit_width + x);
      }
      break;
  }
}

static int cf_v3_image_raster_build_cmy(
    const cf_v3_image_raster_state_t *state, const uint8_t *material,
    size_t material_size, cf_v3_image_pdf_format_result_t *result) {
  size_t size = (size_t)state->explicit_width * state->explicit_height * 3U;
  uint8_t *pixels;

  if (!size || size > CF_V3_IMAGE_RASTER_SPECIAL_MAX_PIXELS ||
      !(pixels = (uint8_t *)malloc(size))) {
    return -1;
  }
  for (unsigned y = 0U; y < state->explicit_height; y++) {
    for (unsigned x = 0U; x < state->explicit_width; x++) {
      cf_v3_image_raster_cmy_source_pixel(
          state, x, y, material, material_size,
          pixels + ((size_t)y * state->explicit_width + x) * 3U);
    }
  }
  result->reference_pixels = pixels;
  result->reference_size = size;
  result->reference_components = 3U;
  result->reference_colorspace = CF_V3_IMAGE_PDF_COLORSPACE_RGB;
  result->width = (uint16_t)state->explicit_width;
  result->height = (uint16_t)state->explicit_height;
  result->xppi = (uint16_t)state->xppi;
  result->yppi = (uint16_t)state->yppi;
  if (cf_v3_image_raster_encode_png(
          pixels, state->explicit_width, state->explicit_height, 3U,
          state->xppi, state->yppi, result) != 0) {
    free(pixels);
    memset(result, 0, sizeof(*result));
    return -1;
  }
  return 0;
}

int cf_v3_image_raster_build_special_source(
    const cf_v3_image_raster_state_t *state, const uint8_t *material,
    size_t material_size, cf_v3_image_pdf_format_result_t *result) {
  if (!state || !result) {
    return -1;
  }
  if (state->profile == CF_V3_IMAGE_RASTER_MULTIPAGE) {
    return cf_v3_image_raster_build_multipage(
               state, material, material_size, result) == 0
               ? 1
               : -1;
  }
  if (state->profile == CF_V3_IMAGE_RASTER_CMY) {
    return cf_v3_image_raster_build_cmy(state, material, material_size,
                                        result) == 0
               ? 1
               : -1;
  }
  return 0;
}
