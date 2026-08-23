// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CF_V2_RASTERTOESCPX_SOURCE
#error "CF_V2_RASTERTOESCPX_SOURCE must be a quoted source path"
#endif

#define CF_V2_MAGIC "ESCPOU1\0"
#define CF_V2_MAGIC_SIZE 8U
#define CF_V2_SELECTOR_SIZE 16U
#define CF_V2_HEADER_SIZE (CF_V2_MAGIC_SIZE + CF_V2_SELECTOR_SIZE)
#define CF_V2_MAX_MATERIAL 4096U
#define CF_V2_MAX_BANDS 16U
#define CF_V2_MAX_LINE 4096U
#define CF_V2_CAPTURE_CAPACITY (4U * CF_V2_MAX_LINE + 128U)

static unsigned char cf_v2_capture[CF_V2_CAPTURE_CAPACITY];
static unsigned char cf_v2_band_buffer[CF_V2_MAX_LINE];
static unsigned char cf_v2_compression_buffer[2U * CF_V2_MAX_LINE + 2U];
static size_t cf_v2_capture_capacity;
static size_t cf_v2_capture_size;

static void
cf_v2_append(const void *data, size_t size)
{
  if (size > cf_v2_capture_capacity - cf_v2_capture_size)
    __builtin_trap();
  memcpy(cf_v2_capture + cf_v2_capture_size, data, size);
  cf_v2_capture_size += size;
}

static int
cf_v2_capture_putchar(int value)
{
  const unsigned char byte = (unsigned char)value;
  cf_v2_append(&byte, 1U);
  return byte;
}

static int
cf_v2_capture_printf(const char *format, ...)
{
  char buffer[64];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  if (result < 0 || (size_t)result >= sizeof(buffer))
    __builtin_trap();
  cf_v2_append(buffer, (size_t)result);
  return result;
}

static size_t
cf_v2_capture_fwrite(const void *data, size_t size, size_t count, FILE *stream)
{
  size_t bytes;

  (void)stream;
  if (size != 0U && count > SIZE_MAX / size)
    __builtin_trap();
  bytes = size * count;
  cf_v2_append(data, bytes);
  return count;
}

static int
cf_v2_quiet_fprintf(FILE *stream, const char *format, ...)
{
  (void)stream;
  (void)format;
  return 0;
}

static int
cf_v2_quiet_fputs(const char *text, FILE *stream)
{
  (void)text;
  (void)stream;
  return 0;
}

#define putchar cf_v2_capture_putchar
#define printf cf_v2_capture_printf
#define fwrite cf_v2_capture_fwrite
#define fprintf cf_v2_quiet_fprintf
#define fputs cf_v2_quiet_fputs
#define main cf_v2_unused_rastertoescpx_main
#include CF_V2_RASTERTOESCPX_SOURCE
#undef main
#undef fputs
#undef fprintf
#undef fwrite
#undef printf
#undef putchar

static const size_t cf_v2_row_bytes[] = {
  1U, 2U, 3U, 7U, 8U, 9U, 31U, 32U, 33U, 127U, 128U, 129U, 255U, 256U
};
static const size_t cf_v2_rows[] = {1U, 2U, 3U, 4U, 8U, 16U};
static const int cf_v2_planes[] = {1, 2, 3, 4, 6, 7};
static const int cf_v2_steps[] = {1, 2, 3, 4, 8, 16};
static const unsigned int cf_v2_resolutions[] = {
  72U, 150U, 300U, 360U, 600U, 720U, 1200U, 1440U
};
static const int cf_v2_origins[] = {-1, 0, 1, 255, 256, 32767, 65535};
static const int cf_v2_offsets[] = {0, 1, 2, 255, 256, 32767, 65535};

static unsigned char
cf_v2_material_byte(const uint8_t *material, size_t material_size,
                    size_t index, unsigned int salt)
{
  return (unsigned char)(material[(index + salt) % material_size] ^
                         (unsigned char)(index * 31U + salt * 17U));
}

static void
cf_v2_fill_band(unsigned char *buffer, size_t length,
                const uint8_t *material, size_t material_size,
                unsigned int pattern, unsigned int salt)
{
  size_t index;

  for (index = 0U; index < length; index ++)
  {
    switch (pattern % 8U)
    {
      case 0U : buffer[index] = 0x00U; break;
      case 1U : buffer[index] = 0xffU; break;
      case 2U : buffer[index] = (index & 1U) ? 0xaaU : 0x55U; break;
      case 3U : buffer[index] = (unsigned char)index; break;
      case 4U : buffer[index] = (unsigned char)(index / 127U); break;
      case 5U :
          buffer[index] = cf_v2_material_byte(material, material_size, index,
                                               salt);
          break;
      case 6U :
          buffer[index] = index < 128U ? 0x5aU : (unsigned char)(index * 29U);
          break;
      default :
          buffer[index] = ((index / 128U) & 1U) ? 0xffU :
              cf_v2_material_byte(material, material_size, index, salt + 1U);
          break;
    }
  }
}

static int
cf_v2_next_y(int origin, size_t index, unsigned int mode,
             unsigned int material)
{
  const int delta = 1 + (int)(material % 1024U);

  switch (mode % 7U)
  {
    case 0U : return origin + (int)index;
    case 1U : return origin + (int)index * delta;
    case 2U : return origin;
    case 3U : return origin - (int)index;
    case 4U : return origin + ((index & 1U) ? -delta : delta);
    case 5U : return (index & 1U) ? 65535 : 0;
    default : return (int)(int16_t)(material + (unsigned int)index * 257U);
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  const size_t *bytes_entry;
  const size_t *rows_entry;
  size_t bytes;
  size_t rows;
  size_t length;
  size_t band_count;
  size_t index;
  int planes;
  int bitplanes;
  int origin;
  ppd_file_t ppd;
  cups_page_header2_t header;
  cups_weave_t band;
  unsigned char *buffer = cf_v2_band_buffer;

  if (!data || size < CF_V2_HEADER_SIZE + 1U ||
      size > CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL ||
      memcmp(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE) != 0)
    return 0;

  selectors = data + CF_V2_MAGIC_SIZE;
  material = data + CF_V2_HEADER_SIZE;
  material_size = size - CF_V2_HEADER_SIZE;
  bytes_entry = &cf_v2_row_bytes[selectors[1] %
      (sizeof(cf_v2_row_bytes) / sizeof(cf_v2_row_bytes[0]))];
  rows_entry = &cf_v2_rows[selectors[2] %
      (sizeof(cf_v2_rows) / sizeof(cf_v2_rows[0]))];
  bytes = *bytes_entry;
  rows = *rows_entry;
  length = bytes * rows;
  band_count = 1U + selectors[0] % CF_V2_MAX_BANDS;
  planes = cf_v2_planes[selectors[3] %
      (sizeof(cf_v2_planes) / sizeof(cf_v2_planes[0]))];
  bitplanes = 1 + (selectors[4] & 1U);
  origin = cf_v2_origins[selectors[11] %
      (sizeof(cf_v2_origins) / sizeof(cf_v2_origins[0]))];

  if (length > CF_V2_MAX_LINE)
    __builtin_trap();
  CompBuffer = cf_v2_compression_buffer;
  cf_v2_capture_capacity = CF_V2_CAPTURE_CAPACITY;

  memset(&ppd, 0, sizeof(ppd));
  memset(&header, 0, sizeof(header));
  memset(&band, 0, sizeof(band));
  if (selectors[5] & 1U)
    ppd.model_number = ESCP_RASTER_ESCI;
  header.cupsCompression = (selectors[5] >> 1U) & 1U;
  header.HWResolution[0] = cf_v2_resolutions[selectors[8] %
      (sizeof(cf_v2_resolutions) / sizeof(cf_v2_resolutions[0]))];
  header.HWResolution[1] = cf_v2_resolutions[selectors[9] %
      (sizeof(cf_v2_resolutions) / sizeof(cf_v2_resolutions[0]))];
  PrinterPlanes = planes;
  BitPlanes = bitplanes;
  DotBufferSize = (int)bytes;
  DotColStep = cf_v2_steps[selectors[6] %
      (sizeof(cf_v2_steps) / sizeof(cf_v2_steps[0]))];
  DotRowStep = cf_v2_steps[selectors[7] %
      (sizeof(cf_v2_steps) / sizeof(cf_v2_steps[0]))];
  DotRowCurrent = origin;

  for (index = 0U; index < band_count; index ++)
  {
    const unsigned int material_value = cf_v2_material_byte(
        material, material_size, index, selectors[15]);
    const int reset = index > 0U &&
        index == 1U + selectors[15] % (unsigned int)(band_count - 1U);
    int previous;
    int expected_feed;
    size_t prefix = 0U;
    size_t byte_index;

    if (band_count > 1U && (selectors[15] & 0x80U) && reset)
      DotRowCurrent = 0;
    previous = DotRowCurrent;
    band.x = cf_v2_offsets[(selectors[13] + (unsigned int)index) %
        (sizeof(cf_v2_offsets) / sizeof(cf_v2_offsets[0]))];
    band.y = cf_v2_next_y(origin, index, selectors[10], material_value);
    band.plane = (int)((selectors[12] + index) % (unsigned int)planes);
    band.row = (int)rows;
    band.count = (int)rows;
    band.dirty = 1;
    band.buffer = buffer;
    cf_v2_fill_band(buffer, length, material, material_size,
                    selectors[14] + (unsigned int)index, material_value);
    expected_feed = band.y - previous;
    cf_v2_capture_size = 0U;

    OutputBand(&ppd, &header, &band);

    if (expected_feed > 0)
    {
      if (cf_v2_capture_size < 8U ||
          memcmp(cf_v2_capture, "\033(v\002\000", 5U) != 0 ||
          cf_v2_capture[5] != (unsigned char)expected_feed ||
          cf_v2_capture[6] != (unsigned char)(expected_feed >> 8U))
        __builtin_trap();
      prefix = 7U;
    }
    if (cf_v2_capture_size <= prefix || cf_v2_capture[prefix] != '\r' ||
        DotRowCurrent != band.y ||
        OutputFeed != (expected_feed > 0 ? 0 : expected_feed) || band.dirty)
      __builtin_trap();
    for (byte_index = 0U; byte_index < length; byte_index ++)
      if (buffer[byte_index] != 0U)
        __builtin_trap();
  }

  CompBuffer = NULL;
  return 0;
}
