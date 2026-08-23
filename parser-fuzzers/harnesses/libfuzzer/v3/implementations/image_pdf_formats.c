// SPDX-License-Identifier: Apache-2.0
#include "image_pdf_formats.h"

#include <stdio.h>
#include <jpeglib.h>
#include <png.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>

#define CF_V3_IMAGE_PDF_MAX_PIXELS                                      \
  ((size_t)CF_V3_IMAGE_PDF_MAX_DIMENSION *                              \
   CF_V3_IMAGE_PDF_MAX_DIMENSION)
#define CF_V3_IMAGE_PDF_MAX_REFERENCE (CF_V3_IMAGE_PDF_MAX_PIXELS * 4U)

typedef struct cf_v3_geometry_s {
  uint16_t width;
  uint16_t height;
} cf_v3_geometry_t;

static const cf_v3_geometry_t cf_v3_geometries[] = {
    {1U, 1U},     {2U, 3U},     {3U, 2U},     {7U, 5U},
    {8U, 8U},     {15U, 17U},   {16U, 16U},   {17U, 15U},
    {31U, 8U},    {32U, 8U},    {33U, 8U},    {63U, 80U},
    {64U, 80U},   {65U, 80U},   {127U, 79U},  {128U, 80U},
    {129U, 81U},  {139U, 199U}, {192U, 160U}, {255U, 3U},
    {256U, 3U},   {257U, 3U},   {3U, 255U},   {3U, 256U},
    {3U, 257U},   {257U, 257U},
};

typedef struct cf_v3_buffer_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
  size_t position;
  int failed;
} cf_v3_buffer_t;

typedef struct cf_v3_jpeg_error_s {
  struct jpeg_error_mgr manager;
  jmp_buf jump;
} cf_v3_jpeg_error_t;

typedef enum cf_v3_tiff_source_e {
  CF_V3_TIFF_GRAY_BLACK8 = 0,
  CF_V3_TIFF_GRAY_WHITE8,
  CF_V3_TIFF_PALETTE8,
  CF_V3_TIFF_RGB8,
  CF_V3_TIFF_RGBA8,
  CF_V3_TIFF_GRAY_ALPHA8,
  CF_V3_TIFF_CMYK8,
  CF_V3_TIFF_GRAY_BLACK_PACKED,
  CF_V3_TIFF_GRAY_WHITE_PACKED,
  CF_V3_TIFF_PALETTE_PACKED,
  CF_V3_TIFF_RGB_PACKED,
  CF_V3_TIFF_CMYK_PACKED,
  CF_V3_TIFF_GRAY_BLACK_PACKED_ALPHA,
  CF_V3_TIFF_GRAY_WHITE_PACKED_ALPHA,
  CF_V3_TIFF_RGBA_PACKED,
  CF_V3_TIFF_SOURCE_COUNT
} cf_v3_tiff_source_t;

typedef struct cf_v3_tiff_plan_s {
  cf_v3_tiff_source_t source;
  uint16_t width;
  uint16_t height;
  uint16_t bits;
  uint16_t channels;
  uint16_t photometric;
  uint16_t compression;
  uint16_t orientation;
  uint32_t rows_per_strip;
  int big_endian;
  int has_alpha;
  int color_output;
  uint32_t relation_flags;
} cf_v3_tiff_plan_t;

static void cf_v3_dimensions(
    const cf_v3_image_pdf_format_request_t *request, uint16_t *width,
    uint16_t *height) {
  const cf_v3_geometry_t *geometry;

  if (request->geometry_selector == 26U) {
    static const cf_v3_geometry_t packed_cache_geometry = {7U, 3U};

    geometry = &packed_cache_geometry;
  } else {
    geometry = &cf_v3_geometries[
        request->geometry_selector %
        (sizeof(cf_v3_geometries) / sizeof(cf_v3_geometries[0]))];
  }

  *width = request->explicit_width ? request->explicit_width : geometry->width;
  *height =
      request->explicit_height ? request->explicit_height : geometry->height;
  if (*width > CF_V3_IMAGE_PDF_MAX_DIMENSION) {
    *width = CF_V3_IMAGE_PDF_MAX_DIMENSION;
  }
  if (*height > CF_V3_IMAGE_PDF_MAX_DIMENSION) {
    *height = CF_V3_IMAGE_PDF_MAX_DIMENSION;
  }
}

static uint8_t cf_v3_material(
    const cf_v3_image_pdf_format_request_t *request, size_t index) {
  size_t stride = 1U + request->stride % 31U;

  if (request->material && request->material_size) {
    size_t offset = ((size_t)request->phase + index * stride) %
                    request->material_size;
    return request->material[offset];
  }
  return (uint8_t)(request->phase ^ (uint8_t)(index * 131U) ^
                   (uint8_t)(index >> 5U));
}

static uint8_t cf_v3_sample(
    const cf_v3_image_pdf_format_request_t *request, unsigned x, unsigned y,
    unsigned channel, size_t index, unsigned maximum) {
  unsigned checker = ((x >> 1U) ^ (y >> 1U) ^ channel) & 1U;
  unsigned value;

  switch (request->pattern % 6U) {
    case 0U:
      value = 0U;
      break;
    case 1U:
      value = maximum;
      break;
    case 2U:
      value = x * 3U + y * 5U + channel * 7U + request->phase;
      value %= maximum + 1U;
      break;
    case 3U:
      value = (unsigned)index * 37U + x * 13U + y * 17U +
              request->phase;
      value %= maximum + 1U;
      break;
    case 4U:
      value = checker ? maximum : 0U;
      break;
    default:
      value = ((unsigned)cf_v3_material(request, index) * maximum + 127U) /
              255U;
      break;
  }
  return (uint8_t)value;
}

static uint8_t cf_v3_luminance(uint8_t red, uint8_t green, uint8_t blue) {
  return (uint8_t)((31U * red + 61U * green + 8U * blue) / 100U);
}

static uint8_t cf_v3_png_alpha_over_white(uint8_t color, uint8_t alpha) {
  return (uint8_t)(((unsigned)color * alpha + 255U * (255U - alpha) +
                    127U) /
                   255U);
}

static uint8_t cf_v3_tiff_alpha_over_white(uint8_t color, uint8_t alpha) {
  return (uint8_t)(((unsigned)color * alpha + 255U * (255U - alpha)) /
                   255U);
}

static uint8_t cf_v3_cmyk_channel(uint8_t component, uint8_t black) {
  unsigned total = (unsigned)component + black;

  return total >= 255U ? 0U : (uint8_t)(255U - total);
}

static uint8_t cf_v3_scale_sample(uint8_t sample, unsigned bits) {
  unsigned maximum = (1U << bits) - 1U;

  return (uint8_t)((unsigned)sample * 255U / maximum);
}

static void cf_v3_palette(unsigned bits, uint8_t index, uint8_t *red,
                          uint8_t *green, uint8_t *blue) {
  unsigned maximum = (1U << bits) - 1U;

  *red = (uint8_t)((unsigned)index * 255U / maximum);
  *green = (uint8_t)(((unsigned)index * 73U + 19U) & 255U);
  *blue = (uint8_t)(255U - *red);
}

static void cf_v3_rgb_to_cmyk(uint8_t red, uint8_t green, uint8_t blue,
                              uint8_t *output) {
  unsigned cyan = 255U - red;
  unsigned magenta = 255U - green;
  unsigned yellow = 255U - blue;
  unsigned black = cyan < magenta ? cyan : magenta;
  unsigned maximum = cyan > magenta ? cyan : magenta;

  if (yellow < black) {
    black = yellow;
  }
  if (yellow > maximum) {
    maximum = yellow;
  }
  if (maximum > black) {
    black = black * black * black / (maximum * maximum);
  }
  output[0] = (uint8_t)(cyan - black);
  output[1] = (uint8_t)(magenta - black);
  output[2] = (uint8_t)(yellow - black);
  output[3] = (uint8_t)black;
}

static int cf_v3_buffer_reserve(cf_v3_buffer_t *buffer, size_t wanted) {
  size_t capacity;
  uint8_t *resized;

  if (wanted > CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
    buffer->failed = 1;
    return -1;
  }
  if (wanted <= buffer->capacity) {
    return 0;
  }
  capacity = buffer->capacity ? buffer->capacity : 4096U;
  while (capacity < wanted) {
    size_t next = capacity * 2U;

    if (next < capacity || next > CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
      capacity = CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE;
      break;
    }
    capacity = next;
  }
  resized = (uint8_t *)realloc(buffer->data, capacity);
  if (!resized) {
    buffer->failed = 1;
    return -1;
  }
  buffer->data = resized;
  buffer->capacity = capacity;
  return 0;
}

static int cf_v3_reference_layout(
    cf_v3_image_pdf_format_result_t *result, uint16_t width, uint16_t height,
    uint8_t components, cf_v3_image_pdf_colorspace_t colorspace) {
  size_t size = (size_t)width * height * components;

  if (!size || size > CF_V3_IMAGE_PDF_MAX_REFERENCE) {
    return -1;
  }
  result->reference_pixels = (uint8_t *)malloc(size);
  if (!result->reference_pixels) {
    return -1;
  }
  result->reference_size = size;
  result->reference_components = components;
  result->reference_colorspace = colorspace;
  return 0;
}

static void cf_v3_png_error(png_structp png, png_const_charp message) {
  (void)message;
  longjmp(png_jmpbuf(png), 1);
}

static void cf_v3_png_warning(png_structp png, png_const_charp message) {
  (void)png;
  (void)message;
}

static void cf_v3_png_write(png_structp png, png_bytep data,
                            png_size_t size) {
  cf_v3_buffer_t *buffer = (cf_v3_buffer_t *)png_get_io_ptr(png);

  if (!buffer || size > SIZE_MAX - buffer->size ||
      cf_v3_buffer_reserve(buffer, buffer->size + size) != 0) {
    png_error(png, "bounded PNG output exceeded");
  }
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
}

static void cf_v3_png_flush(png_structp png) { (void)png; }

static int cf_v3_build_png(
    const cf_v3_image_pdf_format_request_t *request, uint16_t width,
    uint16_t height, cf_v3_image_pdf_format_result_t *result) {
  static const int filters[] = {PNG_FILTER_NONE, PNG_FILTER_SUB,
                                PNG_FILTER_UP,   PNG_FILTER_AVG,
                                PNG_FILTER_PAETH, PNG_ALL_FILTERS};
  static const int compression_levels[] = {0, 1, 3, 6, 9};
  static const unsigned packed_depths[] = {1U, 2U, 4U};
  cf_v3_buffer_t *buffer = NULL;
  png_structp png = NULL;
  png_infop info = NULL;
  png_bytep *rows = NULL;
  uint8_t *source = NULL;
  unsigned source_mode = request->source_selector % 3U;
  unsigned source_components = source_mode == 0U ? 1U :
                               source_mode == 1U ? 3U : 4U;
  bool packed_gray = source_mode == 0U &&
                     (request->codec_selectors[3] & 0x80U) != 0U;
  unsigned bit_depth = packed_gray
                           ? packed_depths[(request->codec_selectors[3] & 3U) %
                                           3U]
                           : 8U;
  unsigned reference_components =
      source_mode != 0U && (request->color_selector & 1U) ? 3U : 1U;
  int color_type = source_mode == 0U ? PNG_COLOR_TYPE_GRAY :
                   source_mode == 1U ? PNG_COLOR_TYPE_RGB :
                                       PNG_COLOR_TYPE_RGBA;
  size_t source_row_size = packed_gray
                               ? ((size_t)width * bit_depth + 7U) / 8U
                               : (size_t)width * source_components;
  size_t source_size = source_row_size * height;
  int success = 0;

  buffer = (cf_v3_buffer_t *)calloc(1, sizeof(*buffer));
  rows = (png_bytep *)malloc((size_t)height * sizeof(*rows));
  source = (uint8_t *)calloc(1, source_size);
  if (!buffer || !rows || !source ||
      cf_v3_reference_layout(
          result, width, height, (uint8_t)reference_components,
          reference_components == 1U ? CF_V3_IMAGE_PDF_COLORSPACE_GRAY
                                     : CF_V3_IMAGE_PDF_COLORSPACE_RGB) != 0) {
    goto cleanup;
  }
  for (unsigned y = 0; y < height; y++) {
    rows[y] = source + (size_t)y * source_row_size;
    for (unsigned x = 0; x < width; x++) {
      uint8_t rgba[4] = {0U, 0U, 0U, 255U};
      size_t pixel = (size_t)y * width + x;

      if (packed_gray) {
        unsigned maximum = (1U << bit_depth) - 1U;
        unsigned sample = cf_v3_sample(request, x, y, 0U, pixel, maximum);
        size_t bit_offset = (size_t)x * bit_depth;
        unsigned shift = 8U - bit_depth - (unsigned)(bit_offset & 7U);

        rows[y][bit_offset / 8U] |= (uint8_t)(sample << shift);
        result->reference_pixels[pixel] =
            cf_v3_scale_sample((uint8_t)sample, bit_depth);
        continue;
      }
      for (unsigned channel = 0; channel < source_components; channel++) {
        rgba[channel] = cf_v3_sample(request, x, y, channel,
                                     pixel * source_components + channel,
                                     255U);
        if (source_mode == 2U && channel == 3U &&
            !request->allow_known_boundaries) {
          /* Keep the RGBA/libpng transform active in deploy mode while the
           * current non-opaque white-background relation remains faithful. */
          rgba[channel] = 255U;
        }
        source[pixel * source_components + channel] = rgba[channel];
      }
      if (source_mode == 0U) {
        result->reference_pixels[pixel] = rgba[0];
      } else {
        uint8_t red = rgba[0];
        uint8_t green = rgba[1];
        uint8_t blue = rgba[2];

        /* PNG alpha is composited against the decoder's white background. */
        if (source_mode == 2U) {
          red = cf_v3_png_alpha_over_white(red, rgba[3]);
          green = cf_v3_png_alpha_over_white(green, rgba[3]);
          blue = cf_v3_png_alpha_over_white(blue, rgba[3]);
        }
        if (reference_components == 3U) {
          uint8_t *output = result->reference_pixels + pixel * 3U;
          output[0] = red;
          output[1] = green;
          output[2] = blue;
        } else {
          result->reference_pixels[pixel] =
              cf_v3_luminance(red, green, blue);
        }
      }
    }
  }

  png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, cf_v3_png_error,
                                cf_v3_png_warning);
  if (!png || !(info = png_create_info_struct(png))) {
    goto cleanup;
  }
  if (setjmp(png_jmpbuf(png))) {
    goto cleanup;
  }
  png_set_write_fn(png, buffer, cf_v3_png_write, cf_v3_png_flush);
  png_set_compression_level(
      png, compression_levels[request->codec_selectors[0] % 5U]);
  png_set_filter(png, PNG_FILTER_TYPE_BASE,
                 filters[request->codec_selectors[1] % 6U]);
  png_set_IHDR(png, info, width, height, bit_depth, color_type,
               (request->codec_selectors[2] & 1U) ? PNG_INTERLACE_ADAM7
                                                   : PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
  png_set_pHYs(png, info,
               (png_uint_32)(((uint64_t)result->xppi * 10000U + 127U) /
                             254U),
               (png_uint_32)(((uint64_t)result->yppi * 10000U + 127U) /
                             254U),
               PNG_RESOLUTION_METER);
  png_write_info(png, info);
  png_write_image(png, rows);
  png_write_end(png, info);
  if (!buffer->failed && buffer->size &&
      buffer->size <= CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
    result->encoded_bytes = buffer->data;
    buffer->data = NULL;
    result->encoded_size = buffer->size;
    result->mime = "image/png";
    if (source_mode == 2U) {
      result->relation_flags |= CF_V3_IMAGE_PDF_RELATION_PNG_ALPHA;
    }
    success = 1;
  }

cleanup:
  if (png) {
    png_destroy_write_struct(&png, info ? &info : NULL);
  }
  if (buffer) {
    free(buffer->data);
  }
  free(buffer);
  free(rows);
  free(source);
  return success ? 0 : -1;
}

static void cf_v3_jpeg_error_exit(j_common_ptr cinfo) {
  cf_v3_jpeg_error_t *error = (cf_v3_jpeg_error_t *)cinfo->err;
  longjmp(error->jump, 1);
}

static void cf_v3_jpeg_quiet(j_common_ptr cinfo) { (void)cinfo; }

static int cf_v3_build_jpeg(
    const cf_v3_image_pdf_format_request_t *request, uint16_t width,
    uint16_t height, cf_v3_image_pdf_format_result_t *result) {
  static const int qualities[] = {10, 35, 60, 85, 100};
  static const unsigned restarts[] = {0U, 1U, 4U, 16U};
  struct jpeg_compress_struct *compress = NULL;
  struct jpeg_decompress_struct *decompress = NULL;
  cf_v3_jpeg_error_t *write_error = NULL;
  cf_v3_jpeg_error_t *read_error = NULL;
  uint8_t *source = NULL;
  uint8_t *decoded = NULL;
  JSAMPLE *row = NULL;
  unsigned char *encoded = NULL;
  unsigned long encoded_size = 0;
  unsigned source_mode = request->source_selector % 5U;
  unsigned source_components = source_mode == 0U ? 1U :
                               source_mode == 1U ? 3U : 4U;
  unsigned reference_components = source_mode == 0U ? 1U :
      source_mode == 1U ? ((request->color_selector & 1U) ? 3U : 1U) :
                         ((request->color_selector & 1U) ? 4U : 1U);
  size_t source_size = (size_t)width * height * source_components;
  size_t decoded_size;
  int compress_created = 0;
  int decompress_created = 0;
  int success = 0;
  int saw_adobe = 0;

  /* Current cfImageOpenFP rejects four-component JPEG without an Adobe
   * marker before reaching ImageToPDF's writer. Keep it in faithful mode. */
  if (source_mode == 2U && !request->allow_known_boundaries) {
    source_mode = 3U;
  }
  source_components = source_mode == 0U ? 1U :
                      source_mode == 1U ? 3U : 4U;
  reference_components = source_mode == 0U ? 1U :
      source_mode == 1U ? ((request->color_selector & 1U) ? 3U : 1U) :
                         ((request->color_selector & 1U) ? 4U : 1U);
  source_size = (size_t)width * height * source_components;

  compress = (struct jpeg_compress_struct *)calloc(1, sizeof(*compress));
  decompress =
      (struct jpeg_decompress_struct *)calloc(1, sizeof(*decompress));
  write_error = (cf_v3_jpeg_error_t *)calloc(1, sizeof(*write_error));
  read_error = (cf_v3_jpeg_error_t *)calloc(1, sizeof(*read_error));
  source = (uint8_t *)malloc(source_size);
  if (!compress || !decompress || !write_error || !read_error || !source ||
      cf_v3_reference_layout(
          result, width, height, (uint8_t)reference_components,
          reference_components == 1U ? CF_V3_IMAGE_PDF_COLORSPACE_GRAY :
          reference_components == 3U ? CF_V3_IMAGE_PDF_COLORSPACE_RGB :
                                       CF_V3_IMAGE_PDF_COLORSPACE_CMYK) != 0) {
    goto cleanup;
  }
  for (unsigned y = 0; y < height; y++) {
    for (unsigned x = 0; x < width; x++) {
      for (unsigned channel = 0; channel < source_components; channel++) {
        size_t index = ((size_t)y * width + x) * source_components + channel;
        source[index] =
            cf_v3_sample(request, x, y, channel, index, 255U);
      }
    }
  }

  compress->err = jpeg_std_error(&write_error->manager);
  write_error->manager.error_exit = cf_v3_jpeg_error_exit;
  write_error->manager.output_message = cf_v3_jpeg_quiet;
  if (setjmp(write_error->jump)) {
    goto cleanup;
  }
  jpeg_create_compress(compress);
  compress_created = 1;
  jpeg_mem_dest(compress, &encoded, &encoded_size);
  compress->image_width = width;
  compress->image_height = height;
  compress->input_components = (int)source_components;
  compress->in_color_space = source_mode == 0U ? JCS_GRAYSCALE :
                             source_mode == 1U ? JCS_RGB : JCS_CMYK;
  jpeg_set_defaults(compress);
  if (source_mode >= 2U) {
    jpeg_set_colorspace(compress,
                        source_mode == 4U ? JCS_YCCK : JCS_CMYK);
    compress->write_Adobe_marker = source_mode == 2U ? FALSE : TRUE;
  }
  jpeg_set_quality(compress,
                   qualities[request->codec_selectors[0] % 5U], TRUE);
  compress->optimize_coding =
      (request->codec_selectors[2] & 2U) ? TRUE : FALSE;
  compress->restart_interval =
      restarts[request->codec_selectors[3] % 4U];
  compress->density_unit = 1;
  compress->X_density = (UINT16)result->xppi;
  compress->Y_density = (UINT16)result->yppi;
  if (source_components > 1U) {
    for (int component = 0; component < compress->num_components;
         component++) {
      compress->comp_info[component].h_samp_factor = 1;
      compress->comp_info[component].v_samp_factor = 1;
    }
    if (request->codec_selectors[1] % 3U == 1U) {
      compress->comp_info[0].h_samp_factor = 2;
    } else if (request->codec_selectors[1] % 3U == 2U) {
      compress->comp_info[0].h_samp_factor = 2;
      compress->comp_info[0].v_samp_factor = 2;
    }
  }
  if (request->codec_selectors[2] & 1U) {
    jpeg_simple_progression(compress);
  }
  jpeg_start_compress(compress, TRUE);
  while (compress->next_scanline < compress->image_height) {
    JSAMPROW input = source + (size_t)compress->next_scanline * width *
                                  source_components;
    if (jpeg_write_scanlines(compress, &input, 1U) != 1U) {
      goto cleanup;
    }
  }
  jpeg_finish_compress(compress);
  if (!encoded || !encoded_size ||
      encoded_size > CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
    goto cleanup;
  }

  decompress->err = jpeg_std_error(&read_error->manager);
  read_error->manager.error_exit = cf_v3_jpeg_error_exit;
  read_error->manager.output_message = cf_v3_jpeg_quiet;
  if (setjmp(read_error->jump)) {
    goto cleanup;
  }
  jpeg_create_decompress(decompress);
  decompress_created = 1;
  jpeg_mem_src(decompress, encoded, encoded_size);
  if (jpeg_read_header(decompress, TRUE) != JPEG_HEADER_OK) {
    goto cleanup;
  }
  saw_adobe = decompress->saw_Adobe_marker;
  decompress->out_color_space = source_mode == 0U ? JCS_GRAYSCALE :
                                source_mode == 1U ? JCS_RGB : JCS_CMYK;
  jpeg_calc_output_dimensions(decompress);
  if (!jpeg_start_decompress(decompress) ||
      decompress->output_width != width ||
      decompress->output_height != height ||
      (unsigned)decompress->output_components != source_components) {
    goto cleanup;
  }
  decoded_size =
      (size_t)width * height * decompress->output_components;
  decoded = (uint8_t *)malloc(decoded_size);
  row = (JSAMPLE *)malloc((size_t)width * decompress->output_components);
  if (!decoded || !row || decoded_size > CF_V3_IMAGE_PDF_MAX_REFERENCE) {
    goto cleanup;
  }
  while (decompress->output_scanline < decompress->output_height) {
    unsigned y = decompress->output_scanline;
    JSAMPROW output = row;
    if (jpeg_read_scanlines(decompress, &output, 1U) != 1U) {
      goto cleanup;
    }
    memcpy(decoded + (size_t)y * width * decompress->output_components,
           row, (size_t)width * decompress->output_components);
  }
  if (!jpeg_finish_decompress(decompress)) {
    goto cleanup;
  }

  for (size_t pixel = 0; pixel < (size_t)width * height; pixel++) {
    const uint8_t *input = decoded + pixel * source_components;
    uint8_t *output = result->reference_pixels +
                      pixel * reference_components;

    if (source_mode == 0U) {
      output[0] = input[0];
    } else if (source_mode == 1U) {
      if (reference_components == 3U) {
        memcpy(output, input, 3U);
      } else {
        output[0] = cf_v3_luminance(input[0], input[1], input[2]);
      }
    } else {
      uint8_t normalized[4];
      for (unsigned channel = 0; channel < 4U; channel++) {
        /* Adobe CMYK/YCCK decodes inverted in libjpeg and cfImage normalizes. */
        normalized[channel] = saw_adobe ? (uint8_t)(255U - input[channel])
                                        : input[channel];
      }
      if (reference_components == 4U) {
        memcpy(output, normalized, 4U);
      } else {
        int gray = 255 -
            (31 * normalized[0] + 61 * normalized[1] +
             8 * normalized[2]) /
                100 -
            normalized[3];
        output[0] = gray > 0 ? (uint8_t)gray : 0U;
      }
    }
  }
  result->encoded_bytes = encoded;
  encoded = NULL;
  result->encoded_size = (size_t)encoded_size;
  result->mime = "image/jpeg";
  success = 1;

cleanup:
  if (decompress_created) {
    jpeg_destroy_decompress(decompress);
  }
  if (compress_created) {
    jpeg_destroy_compress(compress);
  }
  free(encoded);
  free(row);
  free(decoded);
  free(source);
  free(read_error);
  free(write_error);
  free(decompress);
  free(compress);
  return success ? 0 : -1;
}

static tmsize_t cf_v3_tiff_read(thandle_t handle, void *data,
                                tmsize_t size) {
  cf_v3_buffer_t *buffer = (cf_v3_buffer_t *)handle;
  size_t available;

  if (!buffer || size < 0 || buffer->position > buffer->size) {
    return (tmsize_t)-1;
  }
  available = buffer->size - buffer->position;
  if ((size_t)size > available) {
    size = (tmsize_t)available;
  }
  memcpy(data, buffer->data + buffer->position, (size_t)size);
  buffer->position += (size_t)size;
  return size;
}

static tmsize_t cf_v3_tiff_write(thandle_t handle, void *data,
                                 tmsize_t size) {
  cf_v3_buffer_t *buffer = (cf_v3_buffer_t *)handle;
  size_t end;

  if (!buffer || size < 0 || (size_t)size > SIZE_MAX - buffer->position) {
    return (tmsize_t)-1;
  }
  end = buffer->position + (size_t)size;
  if (cf_v3_buffer_reserve(buffer, end) != 0) {
    return (tmsize_t)-1;
  }
  if (buffer->position > buffer->size) {
    memset(buffer->data + buffer->size, 0, buffer->position - buffer->size);
  }
  memcpy(buffer->data + buffer->position, data, (size_t)size);
  buffer->position = end;
  if (buffer->size < end) {
    buffer->size = end;
  }
  return size;
}

static toff_t cf_v3_tiff_seek(thandle_t handle, toff_t offset, int whence) {
  cf_v3_buffer_t *buffer = (cf_v3_buffer_t *)handle;
  size_t base;
  size_t position;

  if (!buffer) {
    return (toff_t)-1;
  }
  if (whence == SEEK_SET) {
    base = 0U;
  } else if (whence == SEEK_CUR) {
    base = buffer->position;
  } else if (whence == SEEK_END) {
    base = buffer->size;
  } else {
    return (toff_t)-1;
  }
  if (offset > SIZE_MAX || (size_t)offset > SIZE_MAX - base) {
    return (toff_t)-1;
  }
  position = base + (size_t)offset;
  if (position > CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
    return (toff_t)-1;
  }
  buffer->position = position;
  return (toff_t)position;
}

static int cf_v3_tiff_close(thandle_t handle) {
  (void)handle;
  return 0;
}

static toff_t cf_v3_tiff_size(thandle_t handle) {
  cf_v3_buffer_t *buffer = (cf_v3_buffer_t *)handle;
  return buffer ? (toff_t)buffer->size : 0;
}

static int cf_v3_tiff_map(thandle_t handle, void **base, toff_t *size) {
  (void)handle;
  (void)base;
  (void)size;
  return 0;
}

static void cf_v3_tiff_unmap(thandle_t handle, void *base, toff_t size) {
  (void)handle;
  (void)base;
  (void)size;
}

static void cf_v3_tiff_plan(
    const cf_v3_image_pdf_format_request_t *request, uint16_t width,
    uint16_t height, cf_v3_tiff_plan_t *plan) {
  static const uint16_t compressions[] = {
      COMPRESSION_NONE, COMPRESSION_PACKBITS, COMPRESSION_LZW,
#ifdef COMPRESSION_ADOBE_DEFLATE
      COMPRESSION_ADOBE_DEFLATE
#else
      COMPRESSION_DEFLATE
#endif
  };
  static const uint32_t strip_rows[] = {1U, 2U, 8U, UINT32_MAX};
  static const uint8_t packed_bits[] = {1U, 2U, 4U};
  cf_v3_tiff_source_t source =
      (cf_v3_tiff_source_t)(request->source_selector %
                            CF_V3_TIFF_SOURCE_COUNT);
  uint16_t bits = 8U;

  memset(plan, 0, sizeof(*plan));
  if (!request->allow_known_boundaries) {
    if (source == CF_V3_TIFF_GRAY_BLACK_PACKED_ALPHA) {
      source = CF_V3_TIFF_GRAY_ALPHA8;
    } else if (source == CF_V3_TIFF_GRAY_WHITE_PACKED_ALPHA) {
      source = CF_V3_TIFF_GRAY_ALPHA8;
    } else if (source == CF_V3_TIFF_RGBA_PACKED) {
      source = CF_V3_TIFF_RGBA8;
    }
  }
  plan->source = source;
  plan->width = width;
  plan->height = height;
  plan->orientation = (uint16_t)(ORIENTATION_TOPLEFT +
                                 (request->codec_selectors[2] & 3U));
  plan->big_endian = (request->codec_selectors[2] & 4U) != 0U;
  plan->rows_per_strip = strip_rows[request->codec_selectors[1] % 4U];
  if (plan->rows_per_strip > height) {
    plan->rows_per_strip = height;
  }
  plan->compression =
      compressions[request->codec_selectors[0] %
                   (sizeof(compressions) / sizeof(compressions[0]))];
  if (!TIFFIsCODECConfigured(plan->compression)) {
    plan->compression = COMPRESSION_NONE;
  }

  switch (source) {
    case CF_V3_TIFF_GRAY_BLACK8:
      plan->channels = 1U;
      plan->photometric = PHOTOMETRIC_MINISBLACK;
      break;
    case CF_V3_TIFF_GRAY_WHITE8:
      plan->channels = 1U;
      plan->photometric = PHOTOMETRIC_MINISWHITE;
      break;
    case CF_V3_TIFF_PALETTE8:
      plan->channels = 1U;
      plan->photometric = PHOTOMETRIC_PALETTE;
      break;
    case CF_V3_TIFF_RGB8:
      plan->channels = 3U;
      plan->photometric = PHOTOMETRIC_RGB;
      break;
    case CF_V3_TIFF_RGBA8:
      plan->channels = 4U;
      plan->photometric = PHOTOMETRIC_RGB;
      plan->has_alpha = 1;
      break;
    case CF_V3_TIFF_GRAY_ALPHA8:
      plan->channels = 2U;
      plan->photometric = PHOTOMETRIC_MINISBLACK;
      plan->has_alpha = 1;
      break;
    case CF_V3_TIFF_CMYK8:
      plan->channels = 4U;
      plan->photometric = PHOTOMETRIC_SEPARATED;
      break;
    case CF_V3_TIFF_GRAY_BLACK_PACKED:
    case CF_V3_TIFF_GRAY_WHITE_PACKED:
    case CF_V3_TIFF_PALETTE_PACKED:
      bits = packed_bits[request->codec_selectors[3] % 3U];
      plan->channels = 1U;
      plan->photometric =
          source == CF_V3_TIFF_GRAY_BLACK_PACKED
              ? PHOTOMETRIC_MINISBLACK
              : source == CF_V3_TIFF_GRAY_WHITE_PACKED
                    ? PHOTOMETRIC_MINISWHITE
                    : PHOTOMETRIC_PALETTE;
      break;
    case CF_V3_TIFF_RGB_PACKED:
      bits = packed_bits[request->codec_selectors[3] % 3U];
      if (bits == 2U) {
        if (request->allow_known_boundaries) {
          plan->relation_flags |= CF_V3_IMAGE_PDF_RELATION_TIFF_RGB2;
        } else {
          bits = 4U;
        }
      } else if (bits == 1U && !request->allow_known_boundaries) {
        bits = 4U;
      }
      plan->channels = 3U;
      plan->photometric = PHOTOMETRIC_RGB;
      break;
    case CF_V3_TIFF_CMYK_PACKED:
      bits = packed_bits[request->codec_selectors[3] % 3U];
      if (bits == 1U && !request->allow_known_boundaries) {
        bits = 4U;
      }
      plan->channels = 4U;
      plan->photometric = PHOTOMETRIC_SEPARATED;
      break;
    case CF_V3_TIFF_GRAY_BLACK_PACKED_ALPHA:
    case CF_V3_TIFF_GRAY_WHITE_PACKED_ALPHA:
      bits = (request->codec_selectors[3] & 1U) ? 4U : 2U;
      plan->channels = 2U;
      plan->photometric =
          source == CF_V3_TIFF_GRAY_BLACK_PACKED_ALPHA
              ? PHOTOMETRIC_MINISBLACK
              : PHOTOMETRIC_MINISWHITE;
      plan->has_alpha = 1;
      plan->relation_flags |=
          CF_V3_IMAGE_PDF_RELATION_TIFF_PACKED_ALPHA;
      break;
    case CF_V3_TIFF_RGBA_PACKED:
      bits = (request->codec_selectors[3] & 1U) ? 4U : 2U;
      plan->channels = 4U;
      plan->photometric = PHOTOMETRIC_RGB;
      plan->has_alpha = 1;
      plan->relation_flags |=
          CF_V3_IMAGE_PDF_RELATION_TIFF_PACKED_ALPHA;
      break;
    default:
      break;
  }
  plan->bits = bits;
  plan->color_output =
      plan->photometric != PHOTOMETRIC_MINISBLACK &&
      plan->photometric != PHOTOMETRIC_MINISWHITE &&
      (request->color_selector & 1U) != 0U;
  /* Current V2 oracle has no reliable direct 8-bit CMYK color contract. */
  if (source == CF_V3_TIFF_CMYK8) {
    plan->color_output = 0;
  }
}

static void cf_v3_pack_sample(uint8_t *row, size_t bit_offset,
                              unsigned bits, uint8_t sample) {
  for (unsigned bit = 0; bit < bits; bit++) {
    size_t position = bit_offset + bit;
    if (sample & (1U << (bits - bit - 1U))) {
      row[position / 8U] |= (uint8_t)(0x80U >> (position % 8U));
    }
  }
}

static void cf_v3_tiff_source_rgb(const cf_v3_tiff_plan_t *plan,
                                  const uint8_t *pixel, uint8_t *red,
                                  uint8_t *green, uint8_t *blue) {
  if (plan->photometric == PHOTOMETRIC_PALETTE) {
    cf_v3_palette(plan->bits, pixel[0], red, green, blue);
  } else if (plan->photometric == PHOTOMETRIC_RGB) {
    *red = cf_v3_scale_sample(pixel[0], plan->bits);
    *green = cf_v3_scale_sample(pixel[1], plan->bits);
    *blue = cf_v3_scale_sample(pixel[2], plan->bits);
  } else if (plan->photometric == PHOTOMETRIC_SEPARATED) {
    uint8_t cyan = cf_v3_scale_sample(pixel[0], plan->bits);
    uint8_t magenta = cf_v3_scale_sample(pixel[1], plan->bits);
    uint8_t yellow = cf_v3_scale_sample(pixel[2], plan->bits);
    uint8_t black = cf_v3_scale_sample(pixel[3], plan->bits);
    *red = cf_v3_cmyk_channel(cyan, black);
    *green = cf_v3_cmyk_channel(magenta, black);
    *blue = cf_v3_cmyk_channel(yellow, black);
  } else {
    *red = *green = *blue = cf_v3_scale_sample(pixel[0], plan->bits);
  }
}

static int cf_v3_build_tiff_reference(
    const cf_v3_tiff_plan_t *plan, const uint8_t *source,
    cf_v3_image_pdf_format_result_t *result) {
  uint8_t components = !plan->color_output ? 1U :
                       plan->photometric == PHOTOMETRIC_SEPARATED ? 4U : 3U;
  cf_v3_image_pdf_colorspace_t colorspace =
      components == 1U ? CF_V3_IMAGE_PDF_COLORSPACE_GRAY :
      components == 3U ? CF_V3_IMAGE_PDF_COLORSPACE_RGB :
                         CF_V3_IMAGE_PDF_COLORSPACE_CMYK;

  if (cf_v3_reference_layout(result, plan->width, plan->height, components,
                             colorspace) != 0) {
    return -1;
  }
  for (unsigned y = 0; y < plan->height; y++) {
    unsigned source_y = y;
    if (plan->orientation == ORIENTATION_BOTRIGHT ||
        plan->orientation == ORIENTATION_BOTLEFT) {
      source_y = plan->height - y - 1U;
    }
    for (unsigned x = 0; x < plan->width; x++) {
      unsigned source_x = x;
      const uint8_t *pixel;
      uint8_t *output = result->reference_pixels +
          ((size_t)y * plan->width + x) * components;

      if (plan->orientation == ORIENTATION_TOPRIGHT ||
          plan->orientation == ORIENTATION_BOTRIGHT) {
        source_x = plan->width - x - 1U;
      }
      pixel = source +
          ((size_t)source_y * plan->width + source_x) * plan->channels;

      if (plan->photometric == PHOTOMETRIC_MINISBLACK ||
          plan->photometric == PHOTOMETRIC_MINISWHITE) {
        uint8_t value = cf_v3_scale_sample(pixel[0], plan->bits);
        if (plan->photometric == PHOTOMETRIC_MINISWHITE) {
          value = (uint8_t)(255U - value);
        }
        if (plan->has_alpha) {
          value = cf_v3_tiff_alpha_over_white(
              value, cf_v3_scale_sample(pixel[1], plan->bits));
        }
        output[0] = value;
      } else {
        uint8_t red;
        uint8_t green;
        uint8_t blue;
        cf_v3_tiff_source_rgb(plan, pixel, &red, &green, &blue);
        if (plan->has_alpha) {
          uint8_t alpha =
              cf_v3_scale_sample(pixel[plan->channels - 1U], plan->bits);
          /* TIFF V2 semantics use unassociated alpha over opaque white. */
          red = cf_v3_tiff_alpha_over_white(red, alpha);
          green = cf_v3_tiff_alpha_over_white(green, alpha);
          blue = cf_v3_tiff_alpha_over_white(blue, alpha);
        }
        if (components == 4U) {
          cf_v3_rgb_to_cmyk(red, green, blue, output);
        } else if (components == 3U) {
          output[0] = red;
          output[1] = green;
          output[2] = blue;
        } else {
          output[0] = cf_v3_luminance(red, green, blue);
        }
      }
    }
  }
  return 0;
}

static int cf_v3_build_tiff(
    const cf_v3_image_pdf_format_request_t *request, uint16_t width,
    uint16_t height, cf_v3_image_pdf_format_result_t *result) {
  cf_v3_tiff_plan_t plan;
  cf_v3_buffer_t *buffer = NULL;
  TIFF *tiff = NULL;
  uint8_t *source = NULL;
  uint8_t *row = NULL;
  uint16_t red_map[256] = {0};
  uint16_t green_map[256] = {0};
  uint16_t blue_map[256] = {0};
  uint16_t extra_sample = EXTRASAMPLE_UNASSALPHA;
  size_t source_size;
  size_t row_bits;
  size_t row_size;
  unsigned maximum;
  int complete = 0;
  int success = 0;

  cf_v3_tiff_plan(request, width, height, &plan);
  source_size = (size_t)width * height * plan.channels;
  row_bits = (size_t)width * plan.channels * plan.bits;
  row_size = (row_bits + 7U) / 8U;
  maximum = (1U << plan.bits) - 1U;
  buffer = (cf_v3_buffer_t *)calloc(1, sizeof(*buffer));
  source = (uint8_t *)malloc(source_size);
  row = (uint8_t *)malloc(row_size);
  if (!buffer || !source || !row) {
    goto cleanup;
  }
  for (unsigned y = 0; y < height; y++) {
    for (unsigned x = 0; x < width; x++) {
      for (unsigned channel = 0; channel < plan.channels; channel++) {
        size_t index = ((size_t)y * width + x) * plan.channels + channel;
        source[index] =
            cf_v3_sample(request, x, y, channel, index, maximum);
      }
    }
  }
  if (cf_v3_build_tiff_reference(&plan, source, result) != 0) {
    goto cleanup;
  }

  tiff = TIFFClientOpen("v3-image-pdf", plan.big_endian ? "wb" : "wl",
                        (thandle_t)buffer, cf_v3_tiff_read,
                        cf_v3_tiff_write, cf_v3_tiff_seek,
                        cf_v3_tiff_close, cf_v3_tiff_size, cf_v3_tiff_map,
                        cf_v3_tiff_unmap);
  if (!tiff ||
      !TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, (uint32_t)width) ||
      !TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, (uint32_t)height) ||
      !TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, plan.bits) ||
      !TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, plan.channels) ||
      !TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, plan.photometric) ||
      !TIFFSetField(tiff, TIFFTAG_COMPRESSION, plan.compression) ||
      !TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG) ||
      !TIFFSetField(tiff, TIFFTAG_FILLORDER, FILLORDER_MSB2LSB) ||
      !TIFFSetField(tiff, TIFFTAG_ORIENTATION, plan.orientation) ||
      !TIFFSetField(tiff, TIFFTAG_ROWSPERSTRIP, plan.rows_per_strip) ||
      !TIFFSetField(tiff, TIFFTAG_XRESOLUTION, (double)result->xppi) ||
      !TIFFSetField(tiff, TIFFTAG_YRESOLUTION, (double)result->yppi) ||
      !TIFFSetField(tiff, TIFFTAG_RESOLUTIONUNIT, RESUNIT_INCH)) {
    goto cleanup;
  }
  if (plan.has_alpha &&
      !TIFFSetField(tiff, TIFFTAG_EXTRASAMPLES, 1U, &extra_sample)) {
    goto cleanup;
  }
  if (plan.photometric == PHOTOMETRIC_PALETTE) {
    unsigned entries = 1U << plan.bits;
    for (unsigned index = 0; index < entries; index++) {
      uint8_t red;
      uint8_t green;
      uint8_t blue;
      cf_v3_palette(plan.bits, (uint8_t)index, &red, &green, &blue);
      red_map[index] = (uint16_t)((unsigned)red * 257U);
      green_map[index] = (uint16_t)((unsigned)green * 257U);
      blue_map[index] = (uint16_t)((unsigned)blue * 257U);
    }
    if (!TIFFSetField(tiff, TIFFTAG_COLORMAP, red_map, green_map, blue_map)) {
      goto cleanup;
    }
  }
  if (plan.photometric == PHOTOMETRIC_SEPARATED &&
      (!TIFFSetField(tiff, TIFFTAG_INKSET, INKSET_CMYK)
#ifdef TIFFTAG_NUMBEROFINKS
       || !TIFFSetField(tiff, TIFFTAG_NUMBEROFINKS, 4U)
#endif
           )) {
    goto cleanup;
  }
  for (unsigned y = 0; y < height; y++) {
    size_t base = (size_t)y * width * plan.channels;
    size_t bit_offset = 0U;
    memset(row, 0, row_size);
    if (plan.bits == 8U) {
      memcpy(row, source + base, row_size);
    } else {
      for (unsigned x = 0; x < width; x++) {
        for (unsigned channel = 0; channel < plan.channels; channel++) {
          cf_v3_pack_sample(row, bit_offset, plan.bits,
                            source[base + (size_t)x * plan.channels +
                                   channel]);
          bit_offset += plan.bits;
        }
      }
    }
    if (TIFFWriteScanline(tiff, row, y, 0) < 0) {
      goto cleanup;
    }
  }
  complete = TIFFWriteDirectory(tiff) == 1;
  TIFFClose(tiff);
  tiff = NULL;
  if (!complete || buffer->failed || !buffer->size ||
      buffer->size > CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
    goto cleanup;
  }
  result->encoded_bytes = buffer->data;
  buffer->data = NULL;
  result->encoded_size = buffer->size;
  result->mime = "image/tiff";
  result->relation_flags = plan.relation_flags;
  success = 1;

cleanup:
  if (tiff) {
    TIFFClose(tiff);
  }
  if (buffer) {
    free(buffer->data);
  }
  free(buffer);
  free(row);
  free(source);
  return success ? 0 : -1;
}

int cf_v3_image_pdf_format_build(
    const cf_v3_image_pdf_format_request_t *request,
    cf_v3_image_pdf_format_result_t *result) {
  cf_v3_image_pdf_format_result_t built;
  uint16_t width;
  uint16_t height;
  int status;

  if (!request || !result) {
    return -1;
  }
  memset(&built, 0, sizeof(built));
  cf_v3_dimensions(request, &width, &height);
  built.width = width;
  built.height = height;
  built.xppi = request->xppi ? request->xppi : 72U;
  built.yppi = request->yppi ? request->yppi : 72U;
  built.format = (cf_v3_image_pdf_format_t)(request->format_selector % 3U);
  if (built.format == CF_V3_IMAGE_PDF_FORMAT_PNG) {
    status = cf_v3_build_png(request, width, height, &built);
  } else if (built.format == CF_V3_IMAGE_PDF_FORMAT_JPEG) {
    status = cf_v3_build_jpeg(request, width, height, &built);
  } else {
    status = cf_v3_build_tiff(request, width, height, &built);
  }
  if (status != 0 || !built.encoded_bytes || !built.reference_pixels ||
      !built.encoded_size ||
      built.encoded_size > CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE) {
    cf_v3_image_pdf_format_free(&built);
    return -1;
  }
  *result = built;
  return 0;
}

void cf_v3_image_pdf_format_free(cf_v3_image_pdf_format_result_t *result) {
  if (!result) {
    return;
  }
  free(result->encoded_bytes);
  free(result->reference_pixels);
  memset(result, 0, sizeof(*result));
}
