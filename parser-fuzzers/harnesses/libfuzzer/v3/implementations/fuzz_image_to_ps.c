// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define CF_V2_FILTER_FUNCTION ppdFilterImageToPS
#define CF_V2_TARGET_NAME "fuzz_v3_cupsfilters_image_to_ps"
#define CF_V2_INPUT_MIME "image/png"
#define CF_V2_OUTPUT_MIME "application/postscript"
#define CF_V2_STDIO_STREAM_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v3_image_ps_unused_direct_entrypoint
#include "../../v2/implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <cupsfilters/image-private.h>
#include <math.h>
#include <png.h>
#include <stdbool.h>

#define CF_V3_IMAGE_PS_MAGIC "IMGV3PS1"
#define CF_V3_IMAGE_PS_MAGIC_SIZE 8U
#define CF_V3_IMAGE_PS_SELECTORS 16U
#define CF_V3_IMAGE_PS_HEADER_SIZE \
  (CF_V3_IMAGE_PS_MAGIC_SIZE + CF_V3_IMAGE_PS_SELECTORS)
#define CF_V3_IMAGE_PS_MAX_MATERIAL 256U
#define CF_V3_IMAGE_PS_MIN_INPUT (CF_V3_IMAGE_PS_HEADER_SIZE + 1U)
#define CF_V3_IMAGE_PS_MAX_INPUT \
  (CF_V3_IMAGE_PS_HEADER_SIZE + CF_V3_IMAGE_PS_MAX_MATERIAL)
#define CF_V3_IMAGE_PS_MAX_PAGES 18U
#define CF_V3_IMAGE_PS_MAX_WIDTH 180U
#define CF_V3_IMAGE_PS_MAX_HEIGHT 180U
#define CF_V3_IMAGE_PS_MAX_PNG (256U * 1024U)

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
extern void __real_cfImageClose(cf_image_t *image);

enum cf_v3_image_ps_profile_e {
  CF_V3_IMAGE_PS_OUTPUT = 0,
  CF_V3_IMAGE_PS_SEQUENCE = 1,
  CF_V3_IMAGE_PS_AUTO_FIT = 2,
};

typedef struct cf_v3_image_ps_shape_s {
  unsigned width;
  unsigned height;
} cf_v3_image_ps_shape_t;

typedef struct cf_v3_image_ps_topology_s {
  unsigned xpages;
  unsigned ypages;
} cf_v3_image_ps_topology_t;

typedef struct cf_v3_image_ps_case_s {
  enum cf_v3_image_ps_profile_e profile;
  cf_v3_image_ps_topology_t topology;
  unsigned width;
  unsigned height;
  unsigned tile_width;
  unsigned tile_height;
  unsigned components;
  unsigned language_level;
  unsigned orientation;
  unsigned position;
  unsigned copies;
  unsigned emitted_copies;
  unsigned device_copies;
  unsigned tile_count;
  unsigned page_count;
  unsigned page_size;
  unsigned xppi;
  unsigned yppi;
  unsigned xppm;
  unsigned yppm;
  unsigned pattern;
  unsigned phase;
  unsigned stride;
  unsigned ppd_profile;
  bool color;
  bool collate;
  bool mirror;
  bool faithful;
  const uint8_t *material;
  size_t material_size;
} cf_v3_image_ps_case_t;

typedef struct cf_v3_image_ps_writer_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v3_image_ps_writer_t;

static int cf_v3_image_ps_faithful;

static const cf_v3_image_ps_shape_t cf_v3_image_ps_output_shapes[] = {
    {1U, 1U},   {4U, 1U},   {5U, 1U},   {6U, 1U},   {7U, 1U},
    {13U, 2U},  {14U, 2U},  {26U, 3U},  {27U, 3U},  {39U, 2U},
    {40U, 2U},  {41U, 2U},  {79U, 3U},  {80U, 3U},  {81U, 3U},
    {128U, 7U},
};

static const cf_v3_image_ps_shape_t cf_v3_image_ps_fit_shapes[] = {
    {8U, 32U},  {16U, 32U}, {24U, 32U}, {63U, 64U}, {64U, 64U},
    {64U, 63U}, {32U, 24U}, {32U, 16U}, {32U, 8U},
};

static const cf_v3_image_ps_topology_t cf_v3_image_ps_topologies[] = {
    {2U, 1U}, {1U, 2U}, {2U, 2U}, {3U, 1U},
    {1U, 3U}, {3U, 2U}, {2U, 3U},
};

static void cf_v3_image_ps_rebuild_cache(cf_image_t *image) {
  cf_ic_t *first = NULL;
  cf_ic_t *last = NULL;
  size_t columns;
  size_t rows;

  if (!image || !image->tiles) {
    return;
  }
  columns = image->xsize / CF_TILE_SIZE +
            (image->xsize % CF_TILE_SIZE != 0U);
  rows = image->ysize / CF_TILE_SIZE +
         (image->ysize % CF_TILE_SIZE != 0U);
  if (!columns || !rows || columns > 65536U || rows > 65536U ||
      columns > 1048576U / rows) {
    return;
  }
  for (size_t y = 0; y < rows; y++) {
    for (size_t x = 0; x < columns; x++) {
      cf_ic_t *entry = image->tiles[y][x].ic;
      cf_ic_t *known = first;

      while (known && known != entry) {
        known = known->next;
      }
      if (!entry || known) {
        continue;
      }
      entry->prev = last;
      entry->next = NULL;
      if (last) {
        last->next = entry;
      } else {
        first = entry;
      }
      last = entry;
    }
  }
  image->first = first;
  image->last = last;
}

void __wrap_cfImageClose(cf_image_t *image) {
  if (!cf_v3_image_ps_faithful) {
    cf_v3_image_ps_rebuild_cache(image);
  }
  __real_cfImageClose(image);
}

static bool cf_v3_image_ps_fail(const char **failure, const char *reason) {
  if (failure && !*failure) {
    *failure = reason;
  }
  return false;
}

static void cf_v3_image_ps_decode(const uint8_t *data, size_t size,
                                  cf_v3_image_ps_case_t *test_case) {
  static const unsigned ppis[] = {72U, 150U, 200U, 300U, 600U};
  static const unsigned fit_ppi[][4] = {
      {80U, 80U, 3150U, 3150U},
      {80U, 160U, 3150U, 6300U},
      {160U, 80U, 6300U, 3150U},
  };
  static const unsigned strides[] = {1U, 3U, 5U, 7U, 11U, 17U, 23U, 31U};
  const uint8_t *selector = data + CF_V3_IMAGE_PS_MAGIC_SIZE;
  const unsigned copy_policy = selector[4] % 5U;

  memset(test_case, 0, sizeof(*test_case));
  test_case->profile =
      (enum cf_v3_image_ps_profile_e)(selector[0] % 3U);
  test_case->color = (selector[1] & 1U) != 0U;
  test_case->language_level = (selector[1] & 2U) ? 1U : 2U;
  test_case->mirror = (selector[1] & 4U) != 0U;
  test_case->collate = (selector[1] & 8U) != 0U;
  test_case->faithful = (selector[1] & 0x80U) != 0U;
  test_case->components = test_case->color ? 3U : 1U;
  test_case->orientation = selector[3] % 4U;
  test_case->position = selector[5] % 9U;
  test_case->copies = copy_policy == 0U ? 1U : 2U + ((copy_policy - 1U) & 1U);
  test_case->page_size = selector[6] & 1U;
  test_case->pattern = selector[8] % 6U;
  test_case->phase = selector[9];
  test_case->stride = strides[selector[10] & 7U];
  test_case->ppd_profile = selector[11] % 4U;
  test_case->material = data + CF_V3_IMAGE_PS_HEADER_SIZE;
  test_case->material_size = size - CF_V3_IMAGE_PS_HEADER_SIZE;

  if (test_case->profile == CF_V3_IMAGE_PS_SEQUENCE) {
    /* The page-sequence grammar models the Level 2 device-copy and ASCII85
     * lifecycle. Level 1 remains independently reachable in output/fit. */
    test_case->language_level = 2U;
    test_case->page_size = 1U;
    test_case->topology = cf_v3_image_ps_topologies[
        selector[2] % (sizeof(cf_v3_image_ps_topologies) /
                       sizeof(cf_v3_image_ps_topologies[0]))];
    test_case->tile_width = test_case->orientation & 1U ? 60U : 48U;
    test_case->tile_height = test_case->orientation & 1U ? 48U : 60U;
    test_case->width = test_case->topology.xpages * test_case->tile_width;
    test_case->height = test_case->topology.ypages * test_case->tile_height;
    test_case->xppi = 8U;
    test_case->yppi = 8U;
  } else if (test_case->profile == CF_V3_IMAGE_PS_AUTO_FIT) {
    const cf_v3_image_ps_shape_t *shape =
        &cf_v3_image_ps_fit_shapes[
            selector[2] % (sizeof(cf_v3_image_ps_fit_shapes) /
                           sizeof(cf_v3_image_ps_fit_shapes[0]))];
    const unsigned *resolution = fit_ppi[selector[7] % 3U];

    test_case->width = test_case->tile_width = shape->width;
    test_case->height = test_case->tile_height = shape->height;
    test_case->xppi = resolution[0];
    test_case->yppi = resolution[1];
    test_case->xppm = resolution[2];
    test_case->yppm = resolution[3];
    test_case->copies = 1U;
    test_case->collate = false;
    test_case->mirror = false;
  } else {
    const cf_v3_image_ps_shape_t *shape =
        &cf_v3_image_ps_output_shapes[
            selector[2] % (sizeof(cf_v3_image_ps_output_shapes) /
                           sizeof(cf_v3_image_ps_output_shapes[0]))];

    test_case->width = test_case->tile_width = shape->width;
    test_case->height = test_case->tile_height = shape->height;
    test_case->xppi = ppis[selector[7] % 5U];
    test_case->yppi = test_case->xppi;
    /* Collation is a page-sequence state. A single logical page uses the
     * device-copy path, matching the production output route. */
    test_case->collate = false;
  }
  if (!test_case->faithful && test_case->language_level == 2U &&
      (test_case->tile_width * test_case->components) % 4U != 0U &&
      test_case->tile_height > 1U) {
    if (test_case->profile == CF_V3_IMAGE_PS_OUTPUT) {
      /* Keep an ASCII85 tail, but do not carry it across a second row. */
      test_case->height = test_case->tile_height = 1U;
    } else {
      /* Auto-fit still explores both orientations with a row allocation that
       * can hold the producer's four-byte tail padding. */
      test_case->width = test_case->tile_width =
          (test_case->tile_width + 3U) & ~3U;
    }
  }
  test_case->topology.xpages = test_case->topology.xpages ?: 1U;
  test_case->topology.ypages = test_case->topology.ypages ?: 1U;
  test_case->tile_count =
      test_case->topology.xpages * test_case->topology.ypages;
  test_case->emitted_copies = test_case->collate ? test_case->copies : 1U;
  test_case->device_copies = test_case->collate ? 1U : test_case->copies;
  test_case->page_count = test_case->tile_count * test_case->emitted_copies;
}

static uint8_t cf_v3_image_ps_pixel(const cf_v3_image_ps_case_t *test_case,
                                    unsigned x, unsigned y,
                                    unsigned component, size_t index) {
  const unsigned tile_x = x / test_case->tile_width;
  const unsigned tile_y = y / test_case->tile_height;
  const unsigned tile = tile_x * test_case->topology.ypages + tile_y;
  const uint8_t material = test_case->material[
      (test_case->phase + index * test_case->stride + tile * 7U) %
      test_case->material_size];

  switch (test_case->pattern) {
    case 0U:
      return 0U;
    case 1U:
      return 255U;
    case 2U:
      return (uint8_t)(0x21U + tile * 37U + component * 71U +
                       x * 3U + y * 5U + test_case->phase);
    case 3U:
      return (((x / 4U) + (y / 4U) + tile + component + test_case->phase) &
              1U)
                 ? 255U
                 : 0U;
    case 4U:
      return (uint8_t)(index * 29U + x * 11U + y * 17U + tile * 43U +
                       component * 67U + test_case->phase);
    default:
      return (uint8_t)(material ^ (uint8_t)(index * 131U + x * 7U +
                                             y * 13U + tile * 19U));
  }
}

static uint8_t *cf_v3_image_ps_build_pixels(
    const cf_v3_image_ps_case_t *test_case, size_t *size_out) {
  size_t size;
  uint8_t *pixels;

  if (!test_case->width || !test_case->height || !test_case->components ||
      test_case->width > CF_V3_IMAGE_PS_MAX_WIDTH ||
      test_case->height > CF_V3_IMAGE_PS_MAX_HEIGHT ||
      test_case->width > SIZE_MAX / test_case->height ||
      (size_t)test_case->width * test_case->height >
          SIZE_MAX / test_case->components) {
    return NULL;
  }
  size = (size_t)test_case->width * test_case->height * test_case->components;
  if (!(pixels = (uint8_t *)malloc(size))) {
    return NULL;
  }
  for (unsigned y = 0; y < test_case->height; y++) {
    for (unsigned x = 0; x < test_case->width; x++) {
      for (unsigned component = 0; component < test_case->components;
           component++) {
        const size_t index =
            ((size_t)y * test_case->width + x) * test_case->components +
            component;
        pixels[index] =
            cf_v3_image_ps_pixel(test_case, x, y, component, index);
      }
    }
  }
  *size_out = size;
  return pixels;
}

static void cf_v3_image_ps_png_error(png_structp png,
                                     png_const_charp message) {
  (void)message;
  longjmp(png_jmpbuf(png), 1);
}

static void cf_v3_image_ps_png_warning(png_structp png,
                                       png_const_charp message) {
  (void)png;
  (void)message;
}

static void cf_v3_image_ps_png_write(png_structp png, png_bytep bytes,
                                     png_size_t byte_count) {
  cf_v3_image_ps_writer_t *writer =
      (cf_v3_image_ps_writer_t *)png_get_io_ptr(png);
  const size_t increment = (size_t)byte_count;
  size_t needed;

  if (!writer || increment > CF_V3_IMAGE_PS_MAX_PNG - writer->size) {
    png_error(png, "bounded PNG output exceeded");
  }
  needed = writer->size + increment;
  if (needed > writer->capacity) {
    size_t capacity = writer->capacity ? writer->capacity : 1024U;
    uint8_t *replacement;

    while (capacity < needed && capacity <= CF_V3_IMAGE_PS_MAX_PNG / 2U) {
      capacity *= 2U;
    }
    if (capacity < needed) {
      capacity = needed;
    }
    replacement = (uint8_t *)realloc(writer->data, capacity);
    if (!replacement) {
      png_error(png, "PNG output allocation failed");
    }
    writer->data = replacement;
    writer->capacity = capacity;
  }
  memcpy(writer->data + writer->size, bytes, increment);
  writer->size = needed;
}

static void cf_v3_image_ps_png_flush(png_structp png) { (void)png; }

static uint8_t *cf_v3_image_ps_build_png(
    const cf_v3_image_ps_case_t *test_case, const uint8_t *pixels,
    size_t pixel_size, size_t *png_size) {
  cf_v3_image_ps_writer_t writer = {0};
  png_structp png = NULL;
  png_infop info = NULL;
  uint8_t *result = NULL;
  const size_t row_size =
      (size_t)test_case->width * test_case->components;

  if (pixel_size != row_size * test_case->height ||
      !(png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL,
                                      cf_v3_image_ps_png_error,
                                      cf_v3_image_ps_png_warning)) ||
      !(info = png_create_info_struct(png))) {
    goto cleanup;
  }
  if (setjmp(png_jmpbuf(png))) {
    goto cleanup;
  }
  png_set_write_fn(png, &writer, cf_v3_image_ps_png_write,
                   cf_v3_image_ps_png_flush);
  png_set_IHDR(png, info, test_case->width, test_case->height, 8,
               test_case->color ? PNG_COLOR_TYPE_RGB : PNG_COLOR_TYPE_GRAY,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);
  if (test_case->xppm && test_case->yppm) {
    png_set_pHYs(png, info, test_case->xppm, test_case->yppm,
                 PNG_RESOLUTION_METER);
  }
  png_write_info(png, info);
  for (unsigned y = 0; y < test_case->height; y++) {
    png_write_row(png, (png_bytep)(pixels + (size_t)y * row_size));
  }
  png_write_end(png, info);
  if (writer.size) {
    result = writer.data;
    writer.data = NULL;
    *png_size = writer.size;
  }

cleanup:
  if (png || info) {
    png_destroy_write_struct(png ? &png : NULL, info ? &info : NULL);
  }
  free(writer.data);
  return result;
}

static char *cf_v3_image_ps_build_ppd(
    const cf_v3_image_ps_case_t *test_case, const cf_v2_control_t *control,
    size_t *ppd_size) {
  char *ppd = NULL;
  FILE *stream = open_memstream(&ppd, ppd_size);
  bool valid = false;

  if (!stream) {
    return NULL;
  }
  valid = cf_v2_write_ppd(stream, control, CF_V2_TARGET_NAME) == 0 &&
          fprintf(stream, "*ColorDevice: %s\n*LanguageLevel: \"%u\"\n",
                  test_case->color ? "True" : "False",
                  test_case->language_level) >= 0;
  if (fclose(stream) != 0) {
    valid = false;
  }
  if (!valid) {
    free(ppd);
    ppd = NULL;
  }
  return ppd;
}

static int cf_v3_image_ps_build_options(
    const cf_v3_image_ps_case_t *test_case, char *buffer,
    size_t buffer_size) {
  static const char *const page_sizes[] = {"A4", "Letter"};
  static const char *const positions[] = {
      "center", "top", "top-left", "top-right", "left",
      "right",  "bottom", "bottom-left", "bottom-right"};
  static const unsigned ipp_orientations[] = {3U, 4U, 6U, 5U};
  int length;

  if (test_case->profile == CF_V3_IMAGE_PS_AUTO_FIT) {
    length = snprintf(
        buffer, buffer_size,
        "PageSize=%s ColorModel=%s Resolution=300dpi print-scaling=fit "
        "position=center copies=1 Collate=false mirror=false "
        "gamma=1000 brightness=100 saturation=100 hue=0 emit-jcl=false",
        page_sizes[test_case->page_size],
        test_case->color ? "RGB" : "Gray");
  } else {
    length = snprintf(
        buffer, buffer_size,
        "PageSize=%s ColorModel=%s Resolution=300dpi "
        "orientation-requested=%u position=%s mirror=%s Collate=%s "
        "ppi=%u gamma=1000 brightness=100 saturation=100 hue=0 "
        "emit-jcl=false",
        page_sizes[test_case->page_size],
        test_case->color ? "RGB" : "Gray",
        ipp_orientations[test_case->orientation],
        positions[test_case->position], test_case->mirror ? "true" : "false",
        test_case->collate ? "true" : "false", test_case->xppi);
  }
  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}

static const uint8_t *cf_v3_image_ps_find(const uint8_t *data, size_t size,
                                           const char *needle) {
  const size_t needle_size = strlen(needle);

  if (!data || !needle_size || needle_size > size) {
    return NULL;
  }
  for (size_t offset = 0; offset <= size - needle_size; offset++) {
    if (memcmp(data + offset, needle, needle_size) == 0) {
      return data + offset;
    }
  }
  return NULL;
}

static size_t cf_v3_image_ps_count(const uint8_t *data, size_t size,
                                    const char *needle) {
  const size_t needle_size = strlen(needle);
  size_t count = 0;

  while (needle_size && size >= needle_size) {
    const uint8_t *match = cf_v3_image_ps_find(data, size, needle);

    if (!match) {
      break;
    }
    count++;
    size -= (size_t)(match - data) + needle_size;
    data = match + needle_size;
  }
  return count;
}

static bool cf_v3_image_ps_copy_line(const uint8_t *data, size_t size,
                                     char *line, size_t line_size) {
  size_t length = 0;

  if (!data || !line || line_size < 2U) {
    return false;
  }
  while (length < size && data[length] != (uint8_t)'\n') {
    length++;
  }
  if (length >= size || length >= line_size) {
    return false;
  }
  memcpy(line, data, length);
  line[length] = '\0';
  return true;
}

static bool cf_v3_image_ps_expected_byte(
    const cf_v3_image_ps_case_t *test_case, const uint8_t *pixels,
    size_t pixel_size, unsigned tile, size_t offset, uint8_t *expected) {
  const size_t row_bytes =
      (size_t)test_case->tile_width * test_case->components;
  const unsigned local_y = (unsigned)(offset / row_bytes);
  const size_t row_offset = offset % row_bytes;
  const unsigned local_x = (unsigned)(row_offset / test_case->components);
  const unsigned component =
      (unsigned)(row_offset % test_case->components);
  const unsigned tile_x = tile / test_case->topology.ypages;
  const unsigned tile_y = tile % test_case->topology.ypages;
  const unsigned x = tile_x * test_case->tile_width + local_x;
  const unsigned y = tile_y * test_case->tile_height + local_y;
  const size_t source_offset =
      ((size_t)y * test_case->width + x) * test_case->components + component;

  if (local_y >= test_case->tile_height || x >= test_case->width ||
      y >= test_case->height || source_offset >= pixel_size) {
    return false;
  }
  *expected = pixels[source_offset];
  return true;
}

static bool cf_v3_image_ps_check_byte(
    const cf_v3_image_ps_case_t *test_case, const uint8_t *pixels,
    size_t pixel_size, unsigned tile, size_t *offset, uint8_t value,
    const char **failure) {
  uint8_t expected;

  if (!cf_v3_image_ps_expected_byte(test_case, pixels, pixel_size, tile,
                                    *offset, &expected) ||
      value != expected) {
    return cf_v3_image_ps_fail(failure, "pixel-value");
  }
  (*offset)++;
  return true;
}

static bool cf_v3_image_ps_decode_ascii85(
    const uint8_t *encoded, size_t encoded_size,
    const cf_v3_image_ps_case_t *test_case, const uint8_t *pixels,
    size_t pixel_size, unsigned tile, const char **failure) {
  uint8_t group[5];
  unsigned group_size = 0;
  size_t output_offset = 0;
  const size_t expected_size = (size_t)test_case->tile_width *
                               test_case->tile_height * test_case->components;

  for (size_t index = 0; index < encoded_size; index++) {
    const uint8_t byte = encoded[index];

    if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n' ||
        byte == '\f') {
      continue;
    }
    if (byte == (uint8_t)'z') {
      if (group_size != 0U) {
        return cf_v3_image_ps_fail(failure, "ascii85-z-position");
      }
      for (unsigned zero = 0; zero < 4U; zero++) {
        if (!cf_v3_image_ps_check_byte(test_case, pixels, pixel_size, tile,
                                       &output_offset, 0U, failure)) {
          return false;
        }
      }
      continue;
    }
    if (byte < (uint8_t)'!' || byte > (uint8_t)'u') {
      return cf_v3_image_ps_fail(failure, "ascii85-character");
    }
    group[group_size++] = byte;
    if (group_size == 5U) {
      uint64_t packed = 0;

      for (unsigned digit = 0; digit < 5U; digit++) {
        packed = packed * 85U + (uint64_t)(group[digit] - (uint8_t)'!');
      }
      if (packed > UINT32_MAX) {
        return cf_v3_image_ps_fail(failure, "ascii85-overflow");
      }
      for (unsigned shift = 0; shift < 4U; shift++) {
        const uint8_t value = (uint8_t)(packed >> (24U - shift * 8U));

        if (!cf_v3_image_ps_check_byte(test_case, pixels, pixel_size, tile,
                                       &output_offset, value, failure)) {
          return false;
        }
      }
      group_size = 0U;
    }
  }
  if (group_size == 1U) {
    return cf_v3_image_ps_fail(failure, "ascii85-tail");
  }
  if (group_size > 1U) {
    const unsigned emitted = group_size - 1U;
    uint64_t packed = 0;

    while (group_size < 5U) {
      group[group_size++] = (uint8_t)'u';
    }
    for (unsigned digit = 0; digit < 5U; digit++) {
      packed = packed * 85U + (uint64_t)(group[digit] - (uint8_t)'!');
    }
    if (packed > UINT32_MAX) {
      return cf_v3_image_ps_fail(failure, "ascii85-overflow");
    }
    for (unsigned shift = 0; shift < emitted; shift++) {
      const uint8_t value = (uint8_t)(packed >> (24U - shift * 8U));

      if (!cf_v3_image_ps_check_byte(test_case, pixels, pixel_size, tile,
                                     &output_offset, value, failure)) {
        return false;
      }
    }
  }
  return output_offset == expected_size
             ? true
             : cf_v3_image_ps_fail(failure, "ascii85-length");
}

static int cf_v3_image_ps_hex_nibble(uint8_t byte) {
  if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
    return byte - (uint8_t)'0';
  }
  if (byte >= (uint8_t)'A' && byte <= (uint8_t)'F') {
    return byte - (uint8_t)'A' + 10;
  }
  return -1;
}

static bool cf_v3_image_ps_decode_hex(
    const uint8_t *encoded, size_t encoded_size,
    const cf_v3_image_ps_case_t *test_case, const uint8_t *pixels,
    size_t pixel_size, unsigned tile, const char **failure) {
  size_t output_offset = 0;
  unsigned line_digits = 0;
  int high = -1;
  const size_t expected_size = (size_t)test_case->tile_width *
                               test_case->tile_height * test_case->components;

  if (!encoded_size || encoded[encoded_size - 1U] != (uint8_t)'\n') {
    return cf_v3_image_ps_fail(failure, "hex-final-newline");
  }
  for (size_t index = 0; index < encoded_size; index++) {
    const uint8_t byte = encoded[index];
    int nibble;

    if (byte == (uint8_t)'\n') {
      if (!line_digits || line_digits > 80U || (line_digits & 1U) != 0U ||
          (index + 1U < encoded_size && line_digits != 80U)) {
        return cf_v3_image_ps_fail(failure, "hex-line-width");
      }
      line_digits = 0;
      continue;
    }
    if ((nibble = cf_v3_image_ps_hex_nibble(byte)) < 0) {
      return cf_v3_image_ps_fail(failure, "hex-character");
    }
    line_digits++;
    if (high < 0) {
      high = nibble;
      continue;
    }
    if (!cf_v3_image_ps_check_byte(
            test_case, pixels, pixel_size, tile, &output_offset,
            (uint8_t)((high << 4) | nibble), failure)) {
      return false;
    }
    high = -1;
  }
  return high < 0 && output_offset == expected_size
             ? true
             : cf_v3_image_ps_fail(failure, "hex-length");
}

static bool cf_v3_image_ps_auto_landscape(
    const cf_v3_image_ps_case_t *test_case) {
  long double page_width = test_case->page_size ? 571.0L : 576.0L;
  long double page_height = test_case->page_size ? 818.0L : 720.0L;
  long double image_width =
      (long double)test_case->width / (long double)test_case->xppi;
  long double image_height =
      (long double)test_case->height / (long double)test_case->yppi;
  long double portrait_scale =
      fminl(page_width / image_width, page_height / image_height);
  long double landscape_scale =
      fminl(page_height / image_width, page_width / image_height);

  return image_width * portrait_scale * image_height * portrait_scale <
         image_width * landscape_scale * image_height * landscape_scale;
}

static bool cf_v3_image_ps_validate(
    const cf_v2_run_result_t *result,
    const cf_v3_image_ps_case_t *test_case, const uint8_t *pixels,
    size_t pixel_size, const char **failure) {
  const uint8_t *cursor;
  size_t remaining;
  char marker[192];
  char line[256];
  int marker_size;
  unsigned declared_pages = 0;
  bool landscape = test_case->profile == CF_V3_IMAGE_PS_AUTO_FIT
                       ? cf_v3_image_ps_auto_landscape(test_case)
                       : (test_case->orientation & 1U) != 0U;

  if (!result || !result->captured || !result->output ||
      result->output_size < 64U || result->output_size > CF_V2_CAPTURE_LIMIT ||
      memcmp(result->output, "%!PS-Adobe-3.0\n", 15U) != 0) {
    return cf_v3_image_ps_fail(failure, "postscript-header");
  }
  cursor = cf_v3_image_ps_find(result->output, result->output_size,
                               "%%Pages: ");
  if (!cursor ||
      !cf_v3_image_ps_copy_line(
          cursor,
          result->output_size - (size_t)(cursor - result->output), line,
          sizeof(line)) ||
      sscanf(line, "%%%%Pages: %u", &declared_pages) != 1 ||
      declared_pages != test_case->page_count ||
      cf_v3_image_ps_count(result->output, result->output_size,
                           "%%Page: ") != test_case->page_count ||
      cf_v3_image_ps_count(result->output, result->output_size,
                           "showpage\n") != test_case->page_count ||
      cf_v3_image_ps_count(result->output, result->output_size,
                           "%%EOF\n") != 1U) {
    return cf_v3_image_ps_fail(failure, "dsc-lifecycle");
  }
  marker_size = snprintf(marker, sizeof(marker), "%%%%LanguageLevel: %u\n",
                         test_case->language_level);
  if (marker_size <= 0 || (size_t)marker_size >= sizeof(marker) ||
      !cf_v3_image_ps_find(result->output, result->output_size, marker) ||
      !cf_v3_image_ps_find(
          result->output, result->output_size,
          landscape ? "%%Orientation: Landscape\n"
                    : "%%Orientation: Portrait\n")) {
    return cf_v3_image_ps_fail(failure, "document-state");
  }
  if (test_case->device_copies > 1U) {
    marker_size = snprintf(
        marker, sizeof(marker),
        test_case->language_level == 1U
            ? "/#copies %u def\n"
            : "<</NumCopies %u>>setpagedevice\n",
        test_case->device_copies);
    if (marker_size <= 0 || (size_t)marker_size >= sizeof(marker) ||
        !cf_v3_image_ps_find(result->output, result->output_size, marker)) {
      return cf_v3_image_ps_fail(failure, "copy-device-state");
    }
  }
  if (test_case->mirror !=
      (cf_v3_image_ps_count(result->output, result->output_size,
                            " translate -1 1 scale\n") ==
       test_case->page_count)) {
    return cf_v3_image_ps_fail(failure, "mirror-transform");
  }

  cursor = result->output;
  remaining = result->output_size;
  for (unsigned page_index = 0; page_index < test_case->page_count;
       page_index++) {
    const uint8_t *page = cf_v3_image_ps_find(cursor, remaining, "%%Page: ");
    const uint8_t *page_end;
    size_t page_size;
    unsigned width = 0;
    unsigned height = 0;
    unsigned tile = page_index % test_case->tile_count;

    if (!page) {
      return cf_v3_image_ps_fail(failure, "page-marker");
    }
    page_end = cf_v3_image_ps_find(
        page + 1U, result->output_size - (size_t)(page + 1U - result->output),
        page_index + 1U < test_case->page_count ? "%%Page: " : "%%EOF\n");
    if (!page_end) {
      return cf_v3_image_ps_fail(failure, "page-termination");
    }
    page_size = (size_t)(page_end - page);
    if (test_case->language_level == 1U) {
      const uint8_t *operator;
      const uint8_t *encoded;
      const uint8_t *terminator;

      marker_size = snprintf(
          marker, sizeof(marker),
          test_case->color
              ? "/picture %u string def\n%u %u 8[1 0 0 -1 0 1]"
                "{currentfile picture readhexstring pop} false 3 colorimage\n"
              : "/picture %u string def\n%u %u 8[1 0 0 -1 0 1]"
                "{currentfile picture readhexstring pop} image\n",
          test_case->tile_width * test_case->components,
          test_case->tile_width, test_case->tile_height);
      if (marker_size <= 0 || (size_t)marker_size >= sizeof(marker) ||
          !(operator = cf_v3_image_ps_find(page, page_size, marker))) {
        return cf_v3_image_ps_fail(failure, "level1-image-operator");
      }
      encoded = operator + (size_t)marker_size;
      terminator = cf_v3_image_ps_find(
          encoded, page_size - (size_t)(encoded - page), "grestore\n");
      if (!terminator ||
          !cf_v3_image_ps_decode_hex(
              encoded, (size_t)(terminator - encoded), test_case, pixels,
              pixel_size, tile, failure)) {
        return false;
      }
    } else {
      const uint8_t *dictionary = cf_v3_image_ps_find(
          page, page_size, "<</ImageType 1/Width ");
      const uint8_t *source;
      const uint8_t *encoded;
      const uint8_t *terminator;
      size_t dictionary_remaining;

      if (!dictionary ||
          (dictionary_remaining =
               page_size - (size_t)(dictionary - page)) == 0U ||
          !cf_v3_image_ps_copy_line(dictionary, dictionary_remaining, line,
                                    sizeof(line)) ||
          sscanf(line,
                 "<</ImageType 1/Width %u/Height %u/BitsPerComponent 8",
                 &width, &height) != 2 ||
          width != test_case->tile_width ||
          height != test_case->tile_height ||
          !(source = cf_v3_image_ps_find(
                page, page_size,
                "/DataSource currentfile/ASCII85Decode filter")) ||
          !(encoded = cf_v3_image_ps_find(
                source, page_size - (size_t)(source - page), ">>image\n"))) {
        return cf_v3_image_ps_fail(failure, "level2-image-dictionary");
      }
      encoded += strlen(">>image\n");
      terminator = cf_v3_image_ps_find(
          encoded, page_size - (size_t)(encoded - page), "~>");
      if (!terminator ||
          !cf_v3_image_ps_decode_ascii85(
              encoded, (size_t)(terminator - encoded), test_case, pixels,
              pixel_size, tile, failure)) {
        return false;
      }
    }
    cursor = page_end;
    remaining = result->output_size - (size_t)(cursor - result->output);
  }
  return true;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  const size_t limit = max_size < CF_V3_IMAGE_PS_MAX_INPUT
                           ? max_size
                           : CF_V3_IMAGE_PS_MAX_INPUT;
  size_t suffix_size;

  if (!data || limit < CF_V3_IMAGE_PS_MIN_INPUT) {
    return 0;
  }
  if (size > limit) {
    size = limit;
  }
  if (size < CF_V3_IMAGE_PS_MIN_INPUT) {
    memset(data + size, 0, CF_V3_IMAGE_PS_MIN_INPUT - size);
    size = CF_V3_IMAGE_PS_MIN_INPUT;
  }
  suffix_size = LLVMFuzzerMutate(
      data + CF_V3_IMAGE_PS_MAGIC_SIZE,
      size - CF_V3_IMAGE_PS_MAGIC_SIZE,
      limit - CF_V3_IMAGE_PS_MAGIC_SIZE);
  size = CF_V3_IMAGE_PS_MAGIC_SIZE + suffix_size;
  if (size < CF_V3_IMAGE_PS_MIN_INPUT) {
    memset(data + size, 0, CF_V3_IMAGE_PS_MIN_INPUT - size);
    size = CF_V3_IMAGE_PS_MIN_INPUT;
  }
  memcpy(data, CF_V3_IMAGE_PS_MAGIC, CF_V3_IMAGE_PS_MAGIC_SIZE);
  data[CF_V3_IMAGE_PS_MAGIC_SIZE + 1U] &= 0x7fU;
  (void)seed;
  return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v3_image_ps_case_t test_case;
  cf_v2_control_t control;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result = {0};
  uint8_t *pixels = NULL;
  uint8_t *png = NULL;
  char *ppd = NULL;
  char options[768];
  char title[64];
  size_t pixel_size = 0;
  size_t png_size = 0;
  size_t ppd_size = 0;
  bool trap_after_cleanup = false;
  const char *failure = NULL;
  int executed;

  if (!data || size < CF_V3_IMAGE_PS_MIN_INPUT ||
      size > CF_V3_IMAGE_PS_MAX_INPUT ||
      memcmp(data, CF_V3_IMAGE_PS_MAGIC, CF_V3_IMAGE_PS_MAGIC_SIZE) != 0) {
    return 0;
  }
  cf_v3_image_ps_decode(data, size, &test_case);
  if (!test_case.material_size || !test_case.tile_count ||
      !test_case.page_count || test_case.page_count > CF_V3_IMAGE_PS_MAX_PAGES ||
      !(pixels = cf_v3_image_ps_build_pixels(&test_case, &pixel_size)) ||
      !(png = cf_v3_image_ps_build_png(&test_case, pixels, pixel_size,
                                       &png_size))) {
    goto cleanup;
  }

  memset(&control, 0, sizeof(control));
  control.ppd_profile = (uint8_t)test_case.ppd_profile;
  control.page_size = (uint8_t)test_case.page_size;
  control.color_model = test_case.color ? 1U : 0U;
  control.orientation = (uint8_t)test_case.orientation;
  control.position = (uint8_t)test_case.position;
  control.copies = (uint8_t)(test_case.copies - 1U);
  control.mirror = test_case.mirror;
  if (cf_v3_image_ps_build_options(&test_case, options, sizeof(options)) != 0 ||
      !(ppd = cf_v3_image_ps_build_ppd(&test_case, &control, &ppd_size))) {
    goto cleanup;
  }
  snprintf(title, sizeof(title), "image-ps-v3-%u-%u",
           (unsigned)test_case.profile, test_case.phase);

  memset(&job, 0, sizeof(job));
  job.control = control;
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = (const uint8_t *)title;
  job.title_size = strlen(title);
  job.document = png;
  job.document_size = png_size;
  cf_v3_image_ps_faithful = test_case.faithful;
  executed = cf_v2_execute_direct_job(&job, 1, &result);
  cf_v3_image_ps_faithful = 0;
  if (!executed) {
    goto cleanup;
  }
  if (result.status != 0) {
    failure = "filter-status";
    trap_after_cleanup = true;
  } else if (!cf_v3_image_ps_validate(&result, &test_case, pixels, pixel_size,
                                      &failure)) {
    trap_after_cleanup = true;
  }

cleanup:
  cf_v3_image_ps_faithful = 0;
  cf_v2_free_run_result(&result);
  free(ppd);
  free(png);
  free(pixels);
  if (trap_after_cleanup) {
    fprintf(stderr, "%s: %s\n", CF_V2_TARGET_NAME,
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
