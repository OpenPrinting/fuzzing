#define _GNU_SOURCE

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CF_FUZZ_RASTERTOPCLX_SOURCE
#error "CF_FUZZ_RASTERTOPCLX_SOURCE must be a quoted source path"
#endif
#if defined(CF_FUZZ_PCLX_MODE3_CODEC) == defined(CF_FUZZ_PCLX_MODE10_CODEC)
#error "select exactly one PCLX compression codec"
#endif

#define CF_FUZZ_MAGIC "PCLXCMP1"
#define CF_FUZZ_MAGIC_SIZE 8U
#define CF_FUZZ_SELECTOR_SIZE 12U
#define CF_FUZZ_HEADER_SIZE (CF_FUZZ_MAGIC_SIZE + CF_FUZZ_SELECTOR_SIZE)
#define CF_FUZZ_MAX_MATERIAL 4096U
#define CF_FUZZ_MAX_ROW 1024U

static unsigned char *cf_fuzz_capture;
static size_t cf_fuzz_capture_capacity;
static size_t cf_fuzz_capture_size;

static int
cf_fuzz_capture_printf(const char *format, ...)
{
  (void)format;
  return 0;
}

static size_t
cf_fuzz_capture_fwrite(const void *data, size_t size, size_t count, FILE *stream)
{
  size_t bytes;

  (void)stream;
  if (size != 0U && count > SIZE_MAX / size)
    __builtin_trap();
  bytes = size * count;
  if (bytes > cf_fuzz_capture_capacity - cf_fuzz_capture_size)
    __builtin_trap();
  memcpy(cf_fuzz_capture + cf_fuzz_capture_size, data, bytes);
  cf_fuzz_capture_size += bytes;
  return count;
}

#define printf cf_fuzz_capture_printf
#define fwrite cf_fuzz_capture_fwrite
#define main cf_fuzz_unused_rastertopclx_main
#include CF_FUZZ_RASTERTOPCLX_SOURCE
#undef main
#undef fwrite
#undef printf

static const size_t cf_fuzz_mode3_lengths[] = {
  1U, 2U, 7U, 8U, 9U, 30U, 31U, 32U, 33U,
  254U, 255U, 256U, 257U, 510U, 768U, 1024U
};

static const size_t cf_fuzz_mode10_tuples[] = {
  1U, 2U, 3U, 6U, 7U, 8U, 9U, 30U, 31U, 32U,
  84U, 85U, 86U, 254U, 255U, 256U, 257U, 341U
};

static unsigned char
cf_fuzz_material_byte(const uint8_t *material, size_t material_size,
                    size_t index, unsigned int salt)
{
  unsigned char value = material[(index + salt) % material_size];
  return (unsigned char)(value ^ (unsigned char)(salt * 29U + index * 17U));
}

static void
cf_fuzz_fill_initial_seed(unsigned char *seed, size_t size,
                        const uint8_t *material, size_t material_size,
                        unsigned int pattern)
{
  size_t index;

  for (index = 0; index < size; index ++)
  {
    switch (pattern % 6U)
    {
      case 0U : seed[index] = 0x00U; break;
      case 1U : seed[index] = 0xffU; break;
      case 2U : seed[index] = (index & 1U) ? 0xaaU : 0x55U; break;
      case 3U : seed[index] = (unsigned char)index; break;
      case 4U : seed[index] = cf_fuzz_material_byte(material, material_size,
                                                  index, pattern); break;
      default : seed[index] = (unsigned char)(index * 37U + pattern); break;
    }
  }
}

static void
cf_fuzz_make_row(unsigned char *row, const unsigned char *previous,
               size_t length, const uint8_t *material, size_t material_size,
               const uint8_t *selectors, unsigned int row_number,
               unsigned int plane)
{
  static const size_t prefix_points[] = {
    0U, 1U, 2U, 3U, 7U, 8U, 30U, 31U, 32U, 254U, 255U, 256U
  };
  static const size_t run_points[] = {
    1U, 2U, 3U, 6U, 7U, 8U, 9U, 31U, 32U, 254U, 255U
  };
  size_t prefix = prefix_points[selectors[6] %
                                (sizeof(prefix_points) /
                                 sizeof(prefix_points[0]))];
  size_t run = run_points[selectors[7] %
                          (sizeof(run_points) / sizeof(run_points[0]))];
  unsigned int pattern = (selectors[5] + row_number + plane) % 8U;
  unsigned int delta = 1U + (selectors[8] % 127U);
  size_t index;

  memcpy(row, previous, length);
  if (prefix > length)
    prefix = length;
  if (run > length - prefix)
    run = length - prefix;

  switch (pattern)
  {
    case 0U :
        break;
    case 1U :
        if (prefix < length)
          row[prefix] ^= (unsigned char)delta;
        break;
    case 2U :
        for (index = prefix; index < prefix + run; index ++)
          row[index] = (unsigned char)(previous[index] + delta);
        break;
    case 3U :
        for (index = prefix; index < length; index ++)
          row[index] = (unsigned char)(previous[index] +
                                       ((index & 1U) ? delta : 1U));
        break;
    case 4U :
        for (index = 0; index < length; index ++)
          row[index] = cf_fuzz_material_byte(material, material_size, index,
                                            row_number + plane);
        break;
    case 5U :
        memset(row + prefix, 0x00, length - prefix);
        break;
    case 6U :
        memset(row + prefix, 0xff, length - prefix);
        break;
    default :
        for (index = prefix; index < length; index ++)
          row[index] ^= (unsigned char)(delta + index * 13U);
        break;
  }
}

#ifdef CF_FUZZ_PCLX_MODE3_CODEC
static int
cf_fuzz_decode_mode3(unsigned char *decoded, size_t length,
                   const unsigned char *compressed, size_t compressed_size)
{
  size_t input = 0U;
  size_t output = 0U;

  while (input < compressed_size)
  {
    unsigned int command = compressed[input ++];
    size_t count = 1U + (command >> 5U);
    size_t offset = command & 31U;

    if (offset == 31U)
    {
      unsigned int extension;
      do
      {
        if (input >= compressed_size)
          return 0;
        extension = compressed[input ++];
        if (offset > SIZE_MAX - extension)
          return 0;
        offset += extension;
      }
      while (extension == 255U);
    }
    if (offset > length - output)
      return 0;
    output += offset;
    if (count > length - output || count > compressed_size - input)
      return 0;
    memcpy(decoded + output, compressed + input, count);
    input += count;
    output += count;
  }
  return 1;
}
#endif

#ifdef CF_FUZZ_PCLX_MODE10_CODEC
static int
cf_fuzz_signed_five(unsigned int value)
{
  value &= 31U;
  return (value & 16U) ? (int)value - 32 : (int)value;
}

static int
cf_fuzz_mode10_pixel(unsigned char *decoded, const unsigned char *seed,
                   size_t pixel, int rgb, const unsigned char *compressed,
                   size_t compressed_size, size_t *input)
{
  const size_t index = rgb ? pixel * 3U : pixel;
  int red;
  int green;
  int blue;
  unsigned int first;

  if (*input >= compressed_size)
    return 0;
  first = compressed[(*input) ++];
  if (first & 0x80U)
  {
    unsigned int second;
    int seed_red;
    int seed_green;
    int seed_blue;

    if (*input >= compressed_size)
      return 0;
    second = compressed[(*input) ++];
    seed_red = seed[index];
    seed_green = rgb ? seed[index + 1U] : seed[index];
    seed_blue = rgb ? (seed[index + 2U] & 0xfeU) :
                      (seed[index] & 0xfeU);
    red = seed_red + cf_fuzz_signed_five(first >> 2U);
    green = seed_green +
            cf_fuzz_signed_five(((first & 3U) << 3U) | (second >> 5U));
    blue = seed_blue + 2 * cf_fuzz_signed_five(second);
  }
  else
  {
    unsigned int second;
    unsigned int third;

    if (compressed_size - *input < 2U)
      return 0;
    second = compressed[(*input) ++];
    third = compressed[(*input) ++];
    red = (int)((first << 1U) | (second >> 7U));
    green = (int)(((second & 0x7fU) << 1U) | (third >> 7U));
    blue = (int)((third & 0x7fU) << 1U);
  }
  if (red < 0 || red > 255 || green < 0 || green > 255 ||
      blue < 0 || blue > 255)
    return 0;

  if (rgb)
  {
    decoded[index] = (unsigned char)red;
    decoded[index + 1U] = (unsigned char)green;
    decoded[index + 2U] = (unsigned char)blue;
  }
  else
  {
    if (red != green || blue < red - 1 || blue > red + 1)
      return 0;
    decoded[index] = (unsigned char)red;
  }
  return 1;
}

static int
cf_fuzz_decode_mode10(unsigned char *decoded, const unsigned char *seed,
                    size_t length, int rgb,
                    const unsigned char *compressed, size_t compressed_size)
{
  const size_t pixels = rgb ? length / 3U : length;
  size_t input = 0U;
  size_t pixel = 0U;

  memcpy(decoded, seed, length);
  while (input < compressed_size)
  {
    unsigned int command = compressed[input ++];
    size_t offset = (command >> 3U) & 3U;
    size_t count = (command & 7U) + 1U;
    int extended = (command & 7U) == 7U;

    if (command & 0xe0U)
      return 0;
    if (offset == 3U)
    {
      unsigned int extension;
      do
      {
        if (input >= compressed_size)
          return 0;
        extension = compressed[input ++];
        if (offset > SIZE_MAX - extension)
          return 0;
        offset += extension;
      }
      while (extension == 255U);
    }
    if (offset > pixels - pixel)
      return 0;
    pixel += offset;

    for (;;)
    {
      size_t index;

      if (count > pixels - pixel)
        return 0;
      for (index = 0U; index < count; index ++, pixel ++)
      {
        if (!cf_fuzz_mode10_pixel(decoded, seed, pixel, rgb, compressed,
                                compressed_size, &input))
          return 0;
      }
      if (!extended)
        break;
      if (input >= compressed_size)
        return 0;
      count = compressed[input ++];
      if (count == 0U)
        break;
      extended = count == 255U;
    }
  }
  return 1;
}

static int
cf_fuzz_mode10_matches(const unsigned char *decoded,
                     const unsigned char *line, size_t length, int rgb)
{
  size_t index;

  if (!rgb)
    return memcmp(decoded, line, length) == 0;
  for (index = 0U; index < length; index += 3U)
  {
    int blue_difference;

    if (decoded[index] != line[index] ||
        decoded[index + 1U] != line[index + 1U])
      return 0;
    blue_difference = (int)decoded[index + 2U] - (int)line[index + 2U];
    if (blue_difference < -1 || blue_difference > 1)
      return 0;
  }
  return 1;
}
#endif

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  size_t length;
  size_t line_padding;
  size_t line_capacity;
  size_t seed_capacity;
  size_t comp_capacity;
  size_t planes;
  size_t rows;
  unsigned char *line = NULL;
  unsigned char *seed_history = NULL;
  unsigned char *previous = NULL;
#ifdef CF_FUZZ_PCLX_MODE10_CODEC
  unsigned char *decoded = NULL;
  unsigned char *decoder_seed = NULL;
#endif
  size_t row_number;
  size_t plane;

  if (!data || size < CF_FUZZ_HEADER_SIZE + 1U ||
      size > CF_FUZZ_HEADER_SIZE + CF_FUZZ_MAX_MATERIAL ||
      memcmp(data, CF_FUZZ_MAGIC, CF_FUZZ_MAGIC_SIZE) != 0)
    return 0;

  selectors = data + CF_FUZZ_MAGIC_SIZE;
  material = data + CF_FUZZ_HEADER_SIZE;
  material_size = size - CF_FUZZ_HEADER_SIZE;

#ifdef CF_FUZZ_PCLX_MODE3_CODEC
  length = cf_fuzz_mode3_lengths[selectors[0] %
             (sizeof(cf_fuzz_mode3_lengths) / sizeof(cf_fuzz_mode3_lengths[0]))];
  planes = 1U + selectors[2] % 4U;
  line_padding = 1U;
#else
  PrinterPlanes = (selectors[2] & 1U) ? 3 : 1;
  if (PrinterPlanes == 3)
    length = 3U * cf_fuzz_mode10_tuples[selectors[0] %
                 (sizeof(cf_fuzz_mode10_tuples) /
                  sizeof(cf_fuzz_mode10_tuples[0]))];
  else
    length = cf_fuzz_mode3_lengths[selectors[0] %
             (sizeof(cf_fuzz_mode3_lengths) / sizeof(cf_fuzz_mode3_lengths[0]))];
  planes = 1U;
  line_padding = 3U;
#endif
  if (length == 0U || length > CF_FUZZ_MAX_ROW)
    return 0;

  rows = 1U + selectors[1] % 8U;
  line_capacity = length + line_padding;
  seed_capacity = planes * length + line_padding;
  comp_capacity = 4U * length;

  line = (unsigned char *)malloc(line_capacity);
  seed_history = (unsigned char *)malloc(seed_capacity);
  previous = (unsigned char *)malloc(length);
#ifdef CF_FUZZ_PCLX_MODE10_CODEC
  decoded = (unsigned char *)malloc(length);
  decoder_seed = (unsigned char *)malloc(length);
#endif
  CompBuffer = (unsigned char *)malloc(comp_capacity);
  cf_fuzz_capture = (unsigned char *)malloc(comp_capacity);
  SeedBuffer = seed_history;
  if (!line || !seed_history || !previous || !CompBuffer || !cf_fuzz_capture
#ifdef CF_FUZZ_PCLX_MODE10_CODEC
      || !decoded || !decoder_seed
#endif
      )
    goto cleanup;

  cf_fuzz_capture_capacity = comp_capacity;
  cf_fuzz_fill_initial_seed(seed_history, planes * length, material,
                          material_size, selectors[4]);
  memset(seed_history + planes * length, 0x5a, line_padding);
#ifdef CF_FUZZ_PCLX_MODE10_CODEC
  memcpy(decoder_seed, seed_history, length);
#endif
  SeedInvalid = selectors[3] & 1U;

  for (row_number = 0; row_number < rows; row_number ++)
  {
    for (plane = 0; plane < planes; plane ++)
    {
      unsigned char *plane_seed = SeedBuffer + plane * length;

      memcpy(previous, plane_seed, length);
      cf_fuzz_make_row(line, previous, length, material, material_size,
                     selectors, (unsigned int)row_number,
                     (unsigned int)plane);
      memset(line + length, 0xa5, line_padding);
      line[length] = (unsigned char)(plane_seed[length] ^ 0xffU);
      cf_fuzz_capture_size = 0U;

#ifdef CF_FUZZ_PCLX_MODE3_CODEC
      CompressData(line, (int)length, (int)plane,
                   (plane + 1U == planes) ? 'W' : 'V', 3);
      if (!cf_fuzz_decode_mode3(previous, length, cf_fuzz_capture,
                              cf_fuzz_capture_size) ||
          memcmp(previous, line, length) != 0)
        __builtin_trap();
#else
      CompressData(line, (int)length, 0, 'W', 10);
      if (!cf_fuzz_decode_mode10(decoded, decoder_seed, length,
                               PrinterPlanes == 3, cf_fuzz_capture,
                               cf_fuzz_capture_size) ||
          !cf_fuzz_mode10_matches(decoded, line, length,
                                PrinterPlanes == 3))
        __builtin_trap();
      memcpy(decoder_seed, decoded, length);
#endif
      if (memcmp(plane_seed, line, length) != 0)
        __builtin_trap();
    }
    SeedInvalid = 0;
  }

cleanup:
#ifdef CF_FUZZ_PCLX_MODE10_CODEC
  free(decoder_seed);
  free(decoded);
#endif
  free(cf_fuzz_capture);
  free(CompBuffer);
  free(previous);
  free(seed_history);
  free(line);
  cf_fuzz_capture = NULL;
  cf_fuzz_capture_capacity = 0U;
  cf_fuzz_capture_size = 0U;
  CompBuffer = NULL;
  SeedBuffer = NULL;
  return 0;
}
