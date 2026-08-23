// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "raster_hp_runtime.h"

#include <cups/cups.h>
#include <cups/ppd.h>
#include <cups/raster.h>

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef CF_V3_CUPS_RASTERTOHP_SOURCE
#error "CF_V3_CUPS_RASTERTOHP_SOURCE must name the CUPS rastertohp source"
#endif

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
#define CF_V3_RASTER_HP_HAS_ASAN_REPORT_FD 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) && \
    !defined(CF_V3_RASTER_HP_HAS_ASAN_REPORT_FD)
#include <sanitizer/common_interface_defs.h>
#define CF_V3_RASTER_HP_HAS_ASAN_REPORT_FD 1
#endif

typedef struct cf_v3_raster_hp_capture_s
{
  unsigned char *data;
  size_t size;
  size_t capacity;
  int overflow;
} cf_v3_raster_hp_capture_t;

static cf_v3_raster_hp_capture_t cf_v3_hp_capture;

static int
cf_v3_hp_capture_begin(size_t capacity)
{
  unsigned char *resized;

  if (!capacity)
    capacity = 1U;
  if (capacity > cf_v3_hp_capture.capacity)
  {
    resized = (unsigned char *)realloc(cf_v3_hp_capture.data, capacity);
    if (!resized)
      return 0;
    cf_v3_hp_capture.data = resized;
    cf_v3_hp_capture.capacity = capacity;
  }
  cf_v3_hp_capture.size = 0U;
  cf_v3_hp_capture.overflow = 0;
  return 1;
}

static void
cf_v3_hp_capture_end(void)
{
  cf_v3_hp_capture.size = 0U;
  cf_v3_hp_capture.overflow = 0;
}

__attribute__((destructor)) static void
cf_v3_hp_capture_destroy(void)
{
  free(cf_v3_hp_capture.data);
  memset(&cf_v3_hp_capture, 0, sizeof(cf_v3_hp_capture));
}

static void
cf_v3_hp_capture_append(const void *data, size_t size)
{
  size_t remaining;

  if (!data || !size)
    return;
  remaining = cf_v3_hp_capture.capacity - cf_v3_hp_capture.size;
  if (size > remaining)
  {
    if (remaining)
      memcpy(cf_v3_hp_capture.data + cf_v3_hp_capture.size, data, remaining);
    cf_v3_hp_capture.size = cf_v3_hp_capture.capacity;
    cf_v3_hp_capture.overflow = 1;
    return;
  }
  memcpy(cf_v3_hp_capture.data + cf_v3_hp_capture.size, data, size);
  cf_v3_hp_capture.size += size;
}

static int
cf_v3_hp_capture_vprintf(const char *format, va_list arguments)
{
  char buffer[512];
  int result = vsnprintf(buffer, sizeof(buffer), format, arguments);

  if (result < 0)
    return result;
  if ((size_t)result >= sizeof(buffer))
  {
    cf_v3_hp_capture.overflow = 1;
    return result;
  }
  cf_v3_hp_capture_append(buffer, (size_t)result);
  return result;
}

static int
cf_v3_hp_capture_printf(const char *format, ...)
{
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = cf_v3_hp_capture_vprintf(format, arguments);
  va_end(arguments);
  return result;
}

static int
cf_v3_hp_capture_fprintf(FILE *stream, const char *format, ...)
{
  char buffer[512];
  va_list arguments;
  int result;

  va_start(arguments, format);
  if (stream == stdout)
    result = cf_v3_hp_capture_vprintf(format, arguments);
  else
    result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  return result;
}

static int
cf_v3_hp_capture_putchar(int value)
{
  const unsigned char byte = (unsigned char)value;

  cf_v3_hp_capture_append(&byte, 1U);
  return byte;
}

static size_t
cf_v3_hp_capture_fwrite(const void *data, size_t size, size_t count,
                        FILE *stream)
{
  size_t bytes;

  (void)stream;
  if (size && count > SIZE_MAX / size)
  {
    cf_v3_hp_capture.overflow = 1;
    return 0U;
  }
  bytes = size * count;
  cf_v3_hp_capture_append(data, bytes);
  return count;
}

static int
cf_v3_hp_capture_fflush(FILE *stream)
{
  (void)stream;
  return 0;
}

#define printf cf_v3_hp_capture_printf
#define fprintf cf_v3_hp_capture_fprintf
#define putchar cf_v3_hp_capture_putchar
#define fwrite cf_v3_hp_capture_fwrite
#define fflush cf_v3_hp_capture_fflush
#define main cf_v3_raster_hp_legacy_main
#include CF_V3_CUPS_RASTERTOHP_SOURCE
#undef main
#undef fflush
#undef fwrite
#undef putchar
#undef fprintf
#undef printf

static void
cf_v3_raster_hp_reset_globals(void)
{
  memset(Planes, 0, sizeof(Planes));
  CompBuffer = NULL;
  NumPlanes = 0U;
  Feed = 0U;
  Duplex = 0;
  Page = 0;
  Canceled = 0;
#ifdef CF_V3_CUPS_HP_LEGACY_COLORBITS
  BitBuffer = NULL;
  ColorBits = 0U;
#endif
}

static unsigned char
cf_v3_raster_hp_material(const uint8_t *material, size_t material_size,
                         size_t index, unsigned int pattern,
                         unsigned int phase)
{
  unsigned char value = material_size ?
      material[(index + phase) % material_size] :
      (unsigned char)(index * 37U + phase * 19U + 1U);

  switch (pattern & 7U)
  {
    case 0U: return value;
    case 1U: return 0x00U;
    case 2U: return 0xffU;
    case 3U: return (index & 1U) ? 0xaaU : 0x55U;
    case 4U: return (unsigned char)index;
    case 5U: return (unsigned char)((index / (1U + (phase & 31U))) & 0xffU);
    case 6U: return index < (1U + (phase & 127U)) ? 0x5aU : value;
    default: return value ? value : 0x5aU;
  }
}

static int
cf_v3_raster_hp_decode_rle(unsigned char *output, size_t output_size,
                           const unsigned char *input, size_t input_size)
{
  size_t source = 0U;
  size_t destination = 0U;

  while (source < input_size)
  {
    size_t count;

    if (input_size - source < 2U)
      return 0;
    count = (size_t)input[source] + 1U;
    if (count > output_size - destination)
      return 0;
    memset(output + destination, input[source + 1U], count);
    destination += count;
    source += 2U;
  }
  return destination == output_size;
}

static int
cf_v3_raster_hp_decode_packbits(unsigned char *output, size_t output_size,
                                const unsigned char *input,
                                size_t input_size)
{
  size_t source = 0U;
  size_t destination = 0U;

  while (source < input_size)
  {
    const unsigned int command = input[source ++];

    if (command <= 127U)
    {
      const size_t count = command + 1U;

      if (count > input_size - source || count > output_size - destination)
        return 0;
      memcpy(output + destination, input + source, count);
      source += count;
      destination += count;
    }
    else if (command != 128U)
    {
      const size_t count = 257U - command;

      if (source >= input_size || count > output_size - destination)
        return 0;
      memset(output + destination, input[source ++], count);
      destination += count;
    }
  }
  return destination == output_size;
}

static int
cf_v3_raster_hp_parse_segment(size_t *cursor,
                              const unsigned char *expected,
                              size_t expected_size,
                              unsigned int expected_terminator,
                              unsigned int codec,
                              unsigned char *decoded)
{
  size_t offset = *cursor;
  size_t payload_size = 0U;
  size_t digits = 0U;
  const unsigned char *payload;
  int decoded_ok;

  if (offset > cf_v3_hp_capture.size ||
      cf_v3_hp_capture.size - offset < 5U ||
      memcmp(cf_v3_hp_capture.data + offset, "\033*b", 3U))
    return 0;
  offset += 3U;
  while (offset < cf_v3_hp_capture.size &&
         cf_v3_hp_capture.data[offset] >= '0' &&
         cf_v3_hp_capture.data[offset] <= '9')
  {
    if (payload_size > 1000000U)
      return 0;
    payload_size = payload_size * 10U +
                   (size_t)(cf_v3_hp_capture.data[offset] - '0');
    digits ++;
    offset ++;
  }
  if (!digits || offset >= cf_v3_hp_capture.size ||
      cf_v3_hp_capture.data[offset ++] != expected_terminator ||
      payload_size > cf_v3_hp_capture.size - offset)
    return 0;
  payload = cf_v3_hp_capture.data + offset;
  if (codec == 0U)
    decoded_ok = payload_size == expected_size &&
                 !memcmp(payload, expected, expected_size);
  else if (codec == 1U)
    decoded_ok = cf_v3_raster_hp_decode_rle(decoded, expected_size,
                                             payload, payload_size) &&
                 !memcmp(decoded, expected, expected_size);
  else
    decoded_ok = cf_v3_raster_hp_decode_packbits(decoded, expected_size,
                                                  payload, payload_size) &&
                 !memcmp(decoded, expected, expected_size);
  if (!decoded_ok)
    return 0;
  *cursor = offset + payload_size;
  return 1;
}

int
cf_v3_raster_hp_run_codec(const cf_v3_raster_hp_case_t *test_case,
                          const uint8_t *material, size_t material_size)
{
  static const size_t lengths[] = {
    1U, 2U, 3U, 7U, 8U, 9U, 30U, 31U, 32U, 33U,
    126U, 127U, 128U, 129U, 254U, 255U, 256U, 257U,
    511U, 512U, 1024U, 2048U, 4096U
  };
  size_t length;
  unsigned codec;
  unsigned terminator;
  unsigned char *line = NULL;
  unsigned char *decoded = NULL;
  size_t cursor = 0U;
  int ran = 0;
  int ok = 0;

  if (!test_case || !material_size)
    return 0;
  length = lengths[test_case->selectors[0] %
      (sizeof(lengths) / sizeof(lengths[0]))];
  codec = test_case->selectors[1] % 3U;
  terminator = (test_case->selectors[2] & 1U) ? 'W' : 'V';
  line = (unsigned char *)malloc(length);
  decoded = (unsigned char *)malloc(length);
  CompBuffer = (unsigned char *)malloc(2U * length + 64U);
  if (!line || !decoded || !CompBuffer ||
      !cf_v3_hp_capture_begin(2U * length + 128U))
    goto done;
  for (size_t index = 0U; index < length; index ++)
    line[index] = cf_v3_raster_hp_material(
        material, material_size, index, test_case->selectors[3],
        test_case->selectors[5]);

  ran = 1;
  CompressData(line, (unsigned)length, terminator, codec);
  ok = !cf_v3_hp_capture.overflow &&
       cf_v3_raster_hp_parse_segment(&cursor, line, length,
                                     terminator, codec, decoded) &&
       cursor == cf_v3_hp_capture.size;

done:
  cf_v3_hp_capture_end();
  free(CompBuffer);
  free(decoded);
  free(line);
  cf_v3_raster_hp_reset_globals();
  if (ran && !ok)
    __builtin_trap();
  return 0;
}

int
cf_v3_raster_hp_run_row(const cf_v3_raster_hp_case_t *test_case,
                        const uint8_t *material, size_t material_size)
{
  static const size_t widths[] = {
    1U, 2U, 7U, 8U, 9U, 15U, 16U, 17U, 31U, 32U, 33U,
    63U, 64U, 65U, 127U, 128U, 129U, 255U, 256U, 257U,
    511U, 512U, 1024U, 2048U, 4096U
  };
  static const unsigned plane_counts[] = {1U, 3U, 4U};
  static const size_t paddings[] = {0U, 1U, 7U, 8U};
  static const unsigned feeds[] = {0U, 1U, 2U, 127U, 255U, 1024U};
  cups_page_header2_t header;
  unsigned char *decoded = NULL;
  size_t width;
  size_t output_bytes;
  size_t plane_bytes;
  size_t stride;
  size_t total;
  size_t cursor = 0U;
  unsigned planes;
  unsigned codec;
  unsigned feed;
  int ran = 0;
  int ok = 0;

  if (!test_case || !material_size)
    return 0;
  width = widths[test_case->selectors[0] %
      (sizeof(widths) / sizeof(widths[0]))];
  planes = plane_counts[test_case->selectors[1] %
      (sizeof(plane_counts) / sizeof(plane_counts[0]))];
  output_bytes = (width + 7U) / 8U;
  stride = output_bytes + paddings[test_case->selectors[2] %
      (sizeof(paddings) / sizeof(paddings[0]))];
#ifdef CF_V3_CUPS_HP_PLANAR_BYTES_FIXED
  plane_bytes = stride;
#else
  plane_bytes = output_bytes;
#endif
  total = stride * planes;
  codec = test_case->selectors[3] % 3U;
  feed = feeds[test_case->selectors[4] %
      (sizeof(feeds) / sizeof(feeds[0]))];
  Planes[0] = (unsigned char *)malloc(total + planes);
  decoded = (unsigned char *)malloc(plane_bytes);
  if (!Planes[0] || !decoded ||
      !cf_v3_hp_capture_begin(4U * total + 1024U))
    goto done;
  for (unsigned plane = 1U; plane < planes; plane ++)
    Planes[plane] = Planes[0] + plane * stride;
  for (size_t index = 0U; index < total; index ++)
    Planes[0][index] = cf_v3_raster_hp_material(
        material, material_size, index, test_case->selectors[5],
        test_case->selectors[7]);
  CompBuffer = codec ? (unsigned char *)malloc(2U * total + 64U) : NULL;
  if (codec && !CompBuffer)
    goto done;

  memset(&header, 0, sizeof(header));
  header.cupsWidth = (unsigned)width;
  header.cupsBytesPerLine = (unsigned)total;
  header.cupsBitsPerColor = 1U;
  header.cupsCompression = codec;
  NumPlanes = planes;
  Feed = feed;
#ifdef CF_V3_CUPS_HP_LEGACY_COLORBITS
  ColorBits = 1U;
  BitBuffer = NULL;
#endif
  ran = 1;
  OutputLine(&header);

  if (feed)
  {
    char feed_header[64];
    int feed_size = snprintf(feed_header, sizeof(feed_header),
                             "\033*b%uY", feed);

    if (feed_size < 0 || (size_t)feed_size > cf_v3_hp_capture.size ||
        memcmp(cf_v3_hp_capture.data, feed_header, (size_t)feed_size))
      goto done;
    cursor = (size_t)feed_size;
  }
  if (Feed)
    goto done;
  for (unsigned plane = 0U; plane < planes; plane ++)
    if (!cf_v3_raster_hp_parse_segment(
            &cursor, Planes[plane], plane_bytes,
            plane + 1U < planes ? 'V' : 'W', codec, decoded))
      goto done;
  ok = !cf_v3_hp_capture.overflow && cursor == cf_v3_hp_capture.size;

done:
  cf_v3_hp_capture_end();
  free(CompBuffer);
  free(decoded);
  free(Planes[0]);
  cf_v3_raster_hp_reset_globals();
  if (ran && !ok)
    __builtin_trap();
  return 0;
}

static int
cf_v3_raster_hp_expected_append(cf_v3_raster_hp_capture_t *expected,
                                const void *data, size_t size)
{
  if (!expected || !data || size > expected->capacity - expected->size)
    return 0;
  memcpy(expected->data + expected->size, data, size);
  expected->size += size;
  return 1;
}

static int
cf_v3_raster_hp_expected_printf(cf_v3_raster_hp_capture_t *expected,
                                const char *format, ...)
{
  char buffer[256];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  return result >= 0 && (size_t)result < sizeof(buffer) &&
         cf_v3_raster_hp_expected_append(expected, buffer, (size_t)result);
}

static int
cf_v3_raster_hp_page_code(unsigned height)
{
  static const unsigned heights[] = {
    540U, 595U, 624U, 649U, 684U, 709U, 756U,
    792U, 842U, 1008U, 1191U, 1224U
  };
  static const int codes[] = {80, 25, 90, 91, 81, 100, 1, 2, 26, 3, 27, 6};

  for (size_t index = 0U; index < sizeof(heights) / sizeof(heights[0]);
       index ++)
    if (heights[index] == height)
      return codes[index];
  return -1;
}

static int
cf_v3_raster_hp_expected_start(cf_v3_raster_hp_capture_t *expected,
                               const cups_page_header2_t *header,
                               unsigned page, int have_ppd, double vertical,
                               unsigned planes, int spec_tumble)
{
  const int page_code = cf_v3_raster_hp_page_code(header->PageSize[1]);
  unsigned mode;

#define HP_EXPECT(...) \
  do { if (!cf_v3_raster_hp_expected_printf(expected, __VA_ARGS__)) return 0; } while (0)
  if ((!header->Duplex || (page & 1U)) && header->MediaPosition)
    HP_EXPECT("\033&l%uH", header->MediaPosition);
  if (!header->Duplex || (page & 1U))
  {
    HP_EXPECT("\033&l6D\033&k12H");
    HP_EXPECT("\033&l0O");
    if (page_code >= 0)
      HP_EXPECT("\033&l%dA", page_code);
    HP_EXPECT("\033&l%uP", header->PageSize[1] / 12U);
    HP_EXPECT("\033&l0E");
    HP_EXPECT("\033&l%uX", header->NumCopies);
    if (header->cupsMediaType &&
#ifdef CF_V3_CUPS_HP_LEGACY_COLORBITS
        1
#else
        header->HWResolution[0] == 600U
#endif
       )
      HP_EXPECT("\033&l%uM", header->cupsMediaType);
    mode = spec_tumble ?
        (header->Duplex ? 1U + (header->Tumble != 0U) : 0U) :
        (header->Duplex ? 1U : 0U);
    HP_EXPECT("\033&l%uS", mode);
    HP_EXPECT("\033&l0L");
  }
  else
    HP_EXPECT("\033&a2G");
  HP_EXPECT("\033*t%uR", header->HWResolution[0]);
  if (planes == 4U)
    HP_EXPECT("\033*r-4U");
  else if (planes == 3U)
    HP_EXPECT("\033*r-3U");
  HP_EXPECT("\033*r%uS", header->cupsWidth);
  HP_EXPECT("\033*r%uT", header->cupsHeight);
  HP_EXPECT("\033&a0H");
  if (have_ppd)
    HP_EXPECT("\033&a%.0fV", vertical);
  else
    HP_EXPECT("\033&a0V");
  HP_EXPECT("\033*r1A");
  if (header->cupsCompression)
    HP_EXPECT("\033*b%uM", header->cupsCompression);
#undef HP_EXPECT
  return 1;
}

static int
cf_v3_raster_hp_expected_end(cf_v3_raster_hp_capture_t *expected,
                             unsigned page, int duplex, unsigned planes)
{
  const unsigned char form_feed = '\f';

  if (planes > 1U)
  {
    if (!cf_v3_raster_hp_expected_printf(expected, "\033*rC"))
      return 0;
    if (!(duplex && (page & 1U)) &&
        !cf_v3_raster_hp_expected_printf(expected, "\033&l0H"))
      return 0;
  }
  else
  {
    if (!cf_v3_raster_hp_expected_printf(expected, "\033*r0B"))
      return 0;
    if (!(duplex && (page & 1U)) &&
        !cf_v3_raster_hp_expected_append(expected, &form_feed, 1U))
      return 0;
  }
  return 1;
}

int
cf_v3_raster_hp_run_page(const cf_v3_raster_hp_case_t *test_case,
                         const uint8_t *material, size_t material_size,
                         int spec_tumble)
{
  static const unsigned page_heights[] = {
    540U, 595U, 624U, 649U, 684U, 709U, 756U,
    792U, 842U, 1008U, 1191U, 1224U, 720U, 900U
  };
  static const unsigned media_positions[] = {0U, 1U, 2U, 3U, 4U, 7U};
  static const unsigned copies[] = {1U, 2U, 4U, 9U, 99U};
  static const unsigned media_types[] = {0U, 1U, 2U, 3U, 255U};
  static const unsigned resolutions[] = {150U, 300U, 600U, 1200U};
  static const cups_cspace_t color_spaces[] = {
    CUPS_CSPACE_K, CUPS_CSPACE_CMY, CUPS_CSPACE_KCMY, CUPS_CSPACE_RGB
  };
  static const unsigned widths[] = {
    1U, 8U, 9U, 64U, 127U, 128U, 255U, 256U, 1024U, 4096U
  };
  static const unsigned heights[] = {1U, 2U, 8U, 64U, 256U};
  const uint8_t *selectors;
  cf_v3_raster_hp_capture_t expected;
  cups_page_header2_t header;
  ppd_file_t ppd;
  ppd_size_t ppd_size;
  unsigned page_count;
  unsigned duplex_mode;
  unsigned planes;
  unsigned bytes_per_plane;
  unsigned ppd_mode;
  int have_ppd;
  double vertical;
  int ran = 0;
  int ok = 0;

  if (!test_case || !material_size)
    return 0;
  selectors = test_case->selectors;
  page_count = 1U + selectors[0] % 4U;
  duplex_mode = selectors[2] % 3U;
  ppd_mode = selectors[11] % 3U;
  have_ppd = ppd_mode != 0U;
  memset(&header, 0, sizeof(header));
  header.PageSize[0] = 612U;
  header.PageSize[1] = page_heights[selectors[1] %
      (sizeof(page_heights) / sizeof(page_heights[0]))];
  header.Duplex = duplex_mode != 0U;
  header.Tumble = duplex_mode == 2U;
  header.MediaPosition = media_positions[selectors[3] %
      (sizeof(media_positions) / sizeof(media_positions[0]))];
  header.NumCopies = copies[selectors[4] %
      (sizeof(copies) / sizeof(copies[0]))];
  header.cupsMediaType = media_types[selectors[5] %
      (sizeof(media_types) / sizeof(media_types[0]))];
  header.HWResolution[0] = header.HWResolution[1] =
      resolutions[selectors[6] %
      (sizeof(resolutions) / sizeof(resolutions[0]))];
  header.cupsColorSpace = color_spaces[selectors[7] %
      (sizeof(color_spaces) / sizeof(color_spaces[0]))];
  header.cupsCompression = selectors[8] % 3U;
  header.cupsWidth = widths[selectors[9] %
      (sizeof(widths) / sizeof(widths[0]))];
  header.cupsHeight = heights[selectors[10] %
      (sizeof(heights) / sizeof(heights[0]))];
  header.cupsBitsPerColor = 1U;
  header.cupsBitsPerPixel = 1U;
  header.cupsColorOrder = CUPS_ORDER_PLANAR;
  planes = header.cupsColorSpace == CUPS_CSPACE_KCMY ? 4U :
           header.cupsColorSpace == CUPS_CSPACE_CMY ? 3U : 1U;
  bytes_per_plane = (header.cupsWidth + 7U) / 8U;
  header.cupsBytesPerLine = bytes_per_plane * planes;

  memset(&ppd, 0, sizeof(ppd));
  memset(&ppd_size, 0, sizeof(ppd_size));
  if (ppd_mode == 2U)
  {
    ppd_size.length = 500.0f;
    ppd_size.top = 500.0f;
  }
  else
  {
    ppd_size.length = 500.0f + material[0] % 200U;
    ppd_size.top = (float)(material[material_size > 1U ? 1U : 0U] % 50U);
  }
  ppd.num_sizes = 1;
  ppd.sizes = &ppd_size;
  vertical = 10.0 * (ppd_size.length - ppd_size.top);
  memset(&expected, 0, sizeof(expected));
  expected.capacity = 65536U;
  expected.data = (unsigned char *)malloc(expected.capacity);
  if (!expected.data || !cf_v3_hp_capture_begin(65536U))
    goto done;
  cf_v3_raster_hp_reset_globals();
  ran = 1;
  Setup();
  if (!cf_v3_raster_hp_expected_append(&expected, "\033E", 2U))
    goto done;

  for (unsigned page_index = 0U; page_index < page_count; page_index ++)
  {
    Page = (int)page_index + 1;
    StartPage(have_ppd ? &ppd : NULL, &header);
    if (!cf_v3_raster_hp_expected_start(
            &expected, &header, (unsigned)Page, have_ppd, vertical,
            planes, spec_tumble))
      goto done;
    if (NumPlanes != planes || !Planes[0] || Feed ||
        ((header.cupsCompression != 0U) != (CompBuffer != NULL)))
      goto done;
    for (unsigned plane = 1U; plane < planes; plane ++)
      if (Planes[plane] != Planes[0] + plane * bytes_per_plane)
        goto done;
    EndPage();
    if (!cf_v3_raster_hp_expected_end(
            &expected, (unsigned)Page, header.Duplex, planes))
      goto done;
    cf_v3_raster_hp_reset_globals();
  }
  Shutdown();
  if (!cf_v3_raster_hp_expected_append(&expected, "\033E", 2U))
    goto done;
  ok = !cf_v3_hp_capture.overflow &&
       cf_v3_hp_capture.size == expected.size &&
       !memcmp(cf_v3_hp_capture.data, expected.data, expected.size);

done:
  free(expected.data);
  cf_v3_hp_capture_end();
  cf_v3_raster_hp_reset_globals();
  if (ran && !ok)
    __builtin_trap();
  return 0;
}

static unsigned
cf_v3_raster_hp_plane_count(cups_cspace_t color_space)
{
  if (color_space == CUPS_CSPACE_KCMY)
    return 4U;
  if (color_space == CUPS_CSPACE_CMY)
    return 3U;
  return 1U;
}

static int
cf_v3_raster_hp_write_ppd(int fd,
                          const cf_v3_raster_hp_case_t *test_case)
{
  int output_fd;
  FILE *file;
  int result;

  if (fd < 0 || ftruncate(fd, 0) || lseek(fd, 0, SEEK_SET) < 0 ||
      (output_fd = dup(fd)) < 0)
    return 0;
  file = fdopen(output_fd, "w");
  if (!file)
  {
    close(output_fd);
    return 0;
  }
  result = fprintf(
      file,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"1.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"RasterHPV3\"\n"
      "*NickName: \"RasterHPV3\"\n"
      "*PCFileName: \"HPV3.PPD\"\n"
      "*Product: \"(RasterHPV3)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 2.0\n"
      "*cupsModelNumber: %u\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 rastertohp\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Letter\n"
      "*PageSize Letter/Letter: \"<</PageSize[612 792]>>setpagedevice\"\n"
      "*PageSize A4/A4: \"<</PageSize[595 842]>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*DefaultImageableArea: Letter\n"
      "*ImageableArea Letter/Letter: \"0 0 612 792\"\n"
      "*ImageableArea A4/A4: \"0 0 595 842\"\n"
      "*DefaultPaperDimension: Letter\n"
      "*PaperDimension Letter/Letter: \"612 792\"\n"
      "*PaperDimension A4/A4: \"595 842\"\n",
      test_case->ppd_model);
  if (fclose(file))
    return 0;
  return result >= 0 && lseek(fd, 0, SEEK_SET) >= 0;
}

static int
cf_v3_raster_hp_write_raster(int fd,
                             const cf_v3_raster_hp_case_t *test_case,
                             const uint8_t *material, size_t material_size)
{
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  unsigned char *row = NULL;
  uint64_t plane_bytes;
  uint64_t bytes_per_line;
  uint64_t physical_rows;
  unsigned planes;
  int ok = 0;

  planes = cf_v3_raster_hp_plane_count(test_case->color_space);
  plane_bytes = ((uint64_t)test_case->width * test_case->bits_per_color + 7U) /
                8U;
  if (test_case->color_order == CUPS_ORDER_CHUNKED)
    bytes_per_line = ((uint64_t)test_case->width *
                      test_case->bits_per_color * planes + 7U) / 8U;
  else if (test_case->color_order == CUPS_ORDER_BANDED)
    bytes_per_line = plane_bytes * planes;
  else
    bytes_per_line = plane_bytes;
  physical_rows = test_case->color_order == CUPS_ORDER_PLANAR ?
                      (uint64_t)test_case->height * planes :
                      test_case->height;
  if (!bytes_per_line || bytes_per_line > 8192U || !physical_rows ||
      physical_rows > 4096U ||
      bytes_per_line * physical_rows > 4U * 1024U * 1024U)
    return 0;

  memset(&header, 0, sizeof(header));
  memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
  memcpy(header.cupsPageSizeName,
         test_case->page_height == 842U ? "A4" : "Letter",
         test_case->page_height == 842U ? sizeof("A4") : sizeof("Letter"));
  header.HWResolution[0] = header.HWResolution[1] = test_case->resolution;
  header.PageSize[0] = test_case->page_height == 842U ? 595U : 612U;
  header.PageSize[1] = test_case->page_height;
  header.cupsPageSize[0] = (float)header.PageSize[0];
  header.cupsPageSize[1] = (float)header.PageSize[1];
  header.ImagingBoundingBox[2] = header.PageSize[0];
  header.ImagingBoundingBox[3] = header.PageSize[1];
  header.cupsImagingBBox[2] = (float)header.PageSize[0];
  header.cupsImagingBBox[3] = (float)header.PageSize[1];
  header.cupsWidth = test_case->width;
  header.cupsHeight = test_case->height;
  header.cupsBitsPerColor = test_case->bits_per_color;
  header.cupsBitsPerPixel = test_case->color_order == CUPS_ORDER_CHUNKED ?
      test_case->bits_per_color * planes : test_case->bits_per_color;
  header.cupsBytesPerLine = (unsigned)bytes_per_line;
  header.cupsColorOrder = test_case->color_order;
  header.cupsColorSpace = test_case->color_space;
  header.cupsNumColors = planes;
  header.cupsCompression = test_case->compression;
  header.NumCopies = test_case->copies;
  header.MediaPosition = test_case->media_position;
  header.cupsMediaType = test_case->media_type;
  header.Duplex = test_case->duplex;
  header.Tumble = test_case->tumble;

  if (fd < 0 || ftruncate(fd, 0) || lseek(fd, 0, SEEK_SET) < 0)
    return 0;
  raster = cupsRasterOpen(fd, CUPS_RASTER_WRITE);
  row = (unsigned char *)malloc((size_t)bytes_per_line);
  if (!raster || !row || !cupsRasterWriteHeader2(raster, &header))
    goto done;
  for (uint64_t row_index = 0U; row_index < physical_rows; row_index ++)
  {
    for (size_t offset = 0U; offset < (size_t)bytes_per_line; offset ++)
      row[offset] = cf_v3_raster_hp_material(
          material, material_size,
          (size_t)(row_index * bytes_per_line) + offset,
          test_case->pattern,
          (unsigned)test_case->material_phase + (unsigned)row_index);
    if (cupsRasterWritePixels(raster, row, (unsigned)bytes_per_line) !=
        bytes_per_line)
      goto done;
  }
  ok = 1;

done:
  free(row);
  if (raster)
    cupsRasterClose(raster);
  if (lseek(fd, 0, SEEK_SET) < 0)
    ok = 0;
  return ok;
}

static void
cf_v3_raster_hp_call_main(const char *ppd_path, const char *raster_path,
                          const cf_v3_raster_hp_case_t *test_case)
{
  char options[128];
  char *argv[] = {
    (char *)"rastertohp", (char *)"1", (char *)"libfuzzer",
    (char *)"RasterHPV3", (char *)"1", options,
    (char *)raster_path, NULL
  };
  const char *old_ppd = getenv("PPD");
  char *saved_ppd = old_ppd ? strdup(old_ppd) : NULL;
  struct sigaction saved_sigterm;
  int have_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  int saved_stdout = dup(STDOUT_FILENO);
  int saved_stderr = dup(STDERR_FILENO);
  int sink = open("/dev/null", O_WRONLY);

  snprintf(options, sizeof(options),
           "PageSize=%s copies=%u sides=%s",
           test_case->page_height == 842U ? "A4" : "Letter",
           test_case->copies,
           test_case->duplex ? "two-sided-long-edge" : "one-sided");
  if (saved_stdout < 0 || saved_stderr < 0 || sink < 0 ||
      setenv("PPD", ppd_path, 1))
    goto done;
#ifdef CF_V3_RASTER_HP_HAS_ASAN_REPORT_FD
  __sanitizer_set_report_fd((void *)(intptr_t)saved_stderr);
#endif
  if (dup2(sink, STDOUT_FILENO) < 0 || dup2(sink, STDERR_FILENO) < 0)
    goto done;
  cf_v3_raster_hp_reset_globals();
  (void)cf_v3_raster_hp_legacy_main(7, argv);

done:
  if (saved_stderr >= 0)
  {
    (void)dup2(saved_stderr, STDERR_FILENO);
#ifdef CF_V3_RASTER_HP_HAS_ASAN_REPORT_FD
    __sanitizer_set_report_fd((void *)(intptr_t)STDERR_FILENO);
#endif
  }
  if (saved_stdout >= 0)
    (void)dup2(saved_stdout, STDOUT_FILENO);
  clearerr(stdout);
  clearerr(stderr);
  if (have_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  if (saved_ppd)
    (void)setenv("PPD", saved_ppd, 1);
  else
    (void)unsetenv("PPD");
  free(saved_ppd);
  if (sink >= 0)
    close(sink);
  if (saved_stderr >= 0)
    close(saved_stderr);
  if (saved_stdout >= 0)
    close(saved_stdout);
  cf_v3_raster_hp_reset_globals();
}

int
cf_v3_raster_hp_run_main(const cf_v3_raster_hp_case_t *test_case,
                         const uint8_t *material, size_t material_size)
{
  char ppd_path[64];
  char raster_path[64];
  int ppd_fd = -1;
  int raster_fd = -1;

  if (!test_case || !material_size)
    return 0;
  ppd_fd = memfd_create("cups-v3-raster-hp-ppd", MFD_CLOEXEC);
  raster_fd = memfd_create("cups-v3-raster-hp-raster", MFD_CLOEXEC);
  if (ppd_fd < 0 || raster_fd < 0)
    goto done;
  snprintf(ppd_path, sizeof(ppd_path), "/proc/self/fd/%d", ppd_fd);
  snprintf(raster_path, sizeof(raster_path), "/proc/self/fd/%d", raster_fd);
  if (cf_v3_hp_capture_begin(2U * 1024U * 1024U) &&
      cf_v3_raster_hp_write_ppd(ppd_fd, test_case) &&
      cf_v3_raster_hp_write_raster(raster_fd, test_case,
                                   material, material_size))
    cf_v3_raster_hp_call_main(ppd_path, raster_path, test_case);

done:
  cf_v3_hp_capture_end();
  if (raster_fd >= 0)
    close(raster_fd);
  if (ppd_fd >= 0)
    close(ppd_fd);
  return 0;
}
