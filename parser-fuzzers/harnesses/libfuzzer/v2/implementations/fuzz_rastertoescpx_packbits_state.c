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

#define CF_V2_MAGIC "ESCPPCK1"
#define CF_V2_MAGIC_SIZE 8U
#define CF_V2_SELECTOR_SIZE 12U
#define CF_V2_HEADER_SIZE (CF_V2_MAGIC_SIZE + CF_V2_SELECTOR_SIZE)
#define CF_V2_MAX_MATERIAL 4096U

static unsigned char *cf_v2_capture;
static size_t cf_v2_capture_capacity;
static size_t cf_v2_capture_size;
static size_t cf_v2_last_write_offset;
static size_t cf_v2_last_write_size;

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
  cf_v2_last_write_offset = cf_v2_capture_size;
  cf_v2_last_write_size = bytes;
  cf_v2_append(data, bytes);
  return count;
}

#define putchar cf_v2_capture_putchar
#define printf cf_v2_capture_printf
#define fwrite cf_v2_capture_fwrite
#define main cf_v2_unused_rastertoescpx_main
#include CF_V2_RASTERTOESCPX_SOURCE
#undef main
#undef fwrite
#undef printf
#undef putchar

static const size_t cf_v2_row_bytes[] = {
  1U, 2U, 3U, 7U, 8U, 9U, 30U, 31U, 32U,
  33U, 126U, 127U, 128U, 129U, 254U, 255U, 256U
};
static const size_t cf_v2_rows[] = {1U, 2U, 3U, 4U, 8U, 16U};
static const int cf_v2_planes[] = {1, 2, 3, 4, 6, 7};
static const int cf_v2_steps[] = {1, 2, 4, 8, 24, 72, 144, 255};
static const int cf_v2_offsets[] = {0, 1, 2, 255, 256, 32767, 65535};
static const size_t cf_v2_runs[] = {1U, 2U, 3U, 126U, 127U, 128U};

static unsigned char
cf_v2_material_byte(const uint8_t *material, size_t material_size,
                    size_t index, unsigned int salt)
{
  return (unsigned char)(material[(index + salt) % material_size] ^
                         (unsigned char)(index * 37U + salt * 19U));
}

static void
cf_v2_make_line(unsigned char *line, size_t length, const uint8_t *material,
                size_t material_size, const uint8_t *selectors)
{
  const size_t run = cf_v2_runs[selectors[7] %
      (sizeof(cf_v2_runs) / sizeof(cf_v2_runs[0]))];
  size_t index;

  for (index = 0U; index < length; index ++)
  {
    switch (selectors[6] % 8U)
    {
      case 0U : line[index] = 0x00U; break;
      case 1U : line[index] = 0xffU; break;
      case 2U : line[index] = (index & 1U) ? 0xaaU : 0x55U; break;
      case 3U : line[index] = (unsigned char)index; break;
      case 4U :
          line[index] = cf_v2_material_byte(material, material_size, index,
                                             selectors[11]);
          break;
      case 5U : line[index] = (unsigned char)((index / run) & 0xffU); break;
      case 6U :
          line[index] = index < run ? 0x5aU : (unsigned char)(index * 29U);
          break;
      default :
          line[index] = ((index / run) & 1U) ? 0xffU :
              cf_v2_material_byte(material, material_size, index,
                                  selectors[11] + 1U);
          break;
    }
  }
}

static int
cf_v2_decode_packbits(unsigned char *output, size_t output_size,
                      const unsigned char *input, size_t input_size)
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

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static const unsigned char colors[7][7] = {
    {0, 0, 0, 0, 0, 0, 0}, {0, 16, 0, 0, 0, 0, 0},
    {2, 1, 4, 0, 0, 0, 0}, {2, 1, 4, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0}, {2, 18, 1, 17, 4, 0, 0},
    {2, 18, 1, 17, 4, 0, 16}
  };
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  size_t bytes;
  size_t rows;
  size_t length;
  int planes;
  int plane;
  int bitplanes;
  int model_esci;
  int requested_type;
  int xstep;
  int ystep;
  int offset;
  ppd_file_t ppd;
  unsigned char *line;
  unsigned char *decoded;
  const unsigned char *header;
  const unsigned char *payload;
  unsigned char compression;
  size_t header_size;

  if (size < CF_V2_HEADER_SIZE + 1U ||
      size > CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL ||
      memcmp(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE) != 0)
    return 0;

  selectors = data + CF_V2_MAGIC_SIZE;
  material = data + CF_V2_HEADER_SIZE;
  material_size = size - CF_V2_HEADER_SIZE;
  bytes = cf_v2_row_bytes[selectors[0] %
      (sizeof(cf_v2_row_bytes) / sizeof(cf_v2_row_bytes[0]))];
  rows = cf_v2_rows[selectors[1] %
      (sizeof(cf_v2_rows) / sizeof(cf_v2_rows[0]))];
  length = bytes * rows;
  requested_type = selectors[2] & 1U;
  planes = cf_v2_planes[selectors[3] %
      (sizeof(cf_v2_planes) / sizeof(cf_v2_planes[0]))];
  plane = (int)(selectors[11] % (unsigned int)planes);
  bitplanes = 1 + (selectors[4] & 1U);
  model_esci = selectors[5] & 1U;
  offset = cf_v2_offsets[selectors[8] %
      (sizeof(cf_v2_offsets) / sizeof(cf_v2_offsets[0]))];
  xstep = cf_v2_steps[selectors[9] %
      (sizeof(cf_v2_steps) / sizeof(cf_v2_steps[0]))];
  ystep = cf_v2_steps[selectors[10] %
      (sizeof(cf_v2_steps) / sizeof(cf_v2_steps[0]))];

  line = malloc(length);
  decoded = malloc(length);
  CompBuffer = malloc(2U * length + 2U);
  cf_v2_capture_capacity = length + 64U;
  cf_v2_capture = malloc(cf_v2_capture_capacity);
  if (line == NULL || decoded == NULL || CompBuffer == NULL ||
      cf_v2_capture == NULL)
    __builtin_trap();
  cf_v2_make_line(line, length, material, material_size, selectors);
  memset(&ppd, 0, sizeof(ppd));
  if (model_esci)
    ppd.model_number = ESCP_RASTER_ESCI;
  PrinterPlanes = planes;
  BitPlanes = bitplanes;
  cf_v2_capture_size = 0U;
  cf_v2_last_write_offset = 0U;
  cf_v2_last_write_size = 0U;

  CompressData(&ppd, line, (int)length, plane, requested_type, (int)rows,
               xstep, ystep, offset);

  if (cf_v2_capture_size == 0U || cf_v2_capture[0] != 0x0dU ||
      cf_v2_last_write_size == 0U ||
      cf_v2_last_write_offset + cf_v2_last_write_size != cf_v2_capture_size)
    __builtin_trap();
  payload = cf_v2_capture + cf_v2_last_write_offset;
  header_size = model_esci ? 9U : 8U;
  if (cf_v2_last_write_offset < header_size)
    __builtin_trap();
  header = payload - header_size;

  if (model_esci)
  {
    if (header[0] != 0x1bU || header[1] != 'i' ||
        header[2] != colors[planes - 1][plane] ||
        header[4] != (unsigned char)bitplanes ||
        header[5] != (unsigned char)bytes ||
        header[6] != (unsigned char)(bytes >> 8U) ||
        header[7] != (unsigned char)rows || header[8] != 0U)
      __builtin_trap();
    compression = header[3];
  }
  else
  {
    const size_t bits = bytes * 8U;
    if (header[0] != 0x1bU || header[1] != '.' ||
        header[3] != (unsigned char)ystep ||
        header[4] != (unsigned char)xstep ||
        header[5] != (unsigned char)rows ||
        header[6] != (unsigned char)bits ||
        header[7] != (unsigned char)(bits >> 8U))
      __builtin_trap();
    compression = header[2];
  }

  if (compression == '0')
  {
    if (cf_v2_last_write_size != length || memcmp(payload, line, length) != 0)
      __builtin_trap();
  }
  else if (compression == '1')
  {
    if (!cf_v2_decode_packbits(decoded, length, payload,
                               cf_v2_last_write_size) ||
        memcmp(decoded, line, length) != 0)
      __builtin_trap();
  }
  else
    __builtin_trap();

  free(cf_v2_capture);
  free(CompBuffer);
  free(decoded);
  free(line);
  cf_v2_capture = NULL;
  CompBuffer = NULL;
  return 0;
}
