// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * PCLXRAW1: raw one-bit plane and direct RGB writer state for rastertopclx.
 *
 * Input:
 *   bytes 0..7    "PCLXRAW1"
 *   bytes 8..19   base profile, page-profile stride, width, height, pages,
 *                 writer tuple, compression, row schedule, material pattern,
 *                 writer flags, duplex, and resolution selectors
 *   remaining     1..512 bytes of cyclic row material
 *
 * Every selector value maps to a finite state.  The full harness writes one
 * to four complete CUPS Raster pages, invokes the real legacy filter main,
 * captures its PCL/PJL output, parses the complete job/page framing, decodes
 * compression modes 0/1/2, and compares every emitted plane with an
 * independently reconstructed source row.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CF_V2_PCLXRAW_MAGIC "PCLXRAW1"
#define CF_V2_PCLXRAW_MAGIC_SIZE 8U
#define CF_V2_PCLXRAW_SELECTOR_SIZE 12U
#define CF_V2_PCLXRAW_HEADER_SIZE \
  (CF_V2_PCLXRAW_MAGIC_SIZE + CF_V2_PCLXRAW_SELECTOR_SIZE)
#define CF_V2_PCLXRAW_MIN_MATERIAL 1U
#define CF_V2_PCLXRAW_MAX_MATERIAL 512U
#define CF_V2_PCLXRAW_MAX_PAGES 4U
#define CF_V2_PCLXRAW_MAX_WIDTH 128U
#define CF_V2_PCLXRAW_MAX_HEIGHT 16U
#define CF_V2_PCLXRAW_MAX_ROW_BYTES (CF_V2_PCLXRAW_MAX_WIDTH * 3U)
#define CF_V2_PCLXRAW_MAX_CAPTURE (128U * 1024U)

#define CF_V2_PCLXRAW_END_COLOR 1U
#define CF_V2_PCLXRAW_PJL 2U

typedef enum cf_v2_pclxraw_profile_e
{
  CF_V2_PCLXRAW_K1 = 0,
  CF_V2_PCLXRAW_W1,
  CF_V2_PCLXRAW_RGB1,
  CF_V2_PCLXRAW_CMY1,
  CF_V2_PCLXRAW_CMYK1,
  CF_V2_PCLXRAW_RGB24,
  CF_V2_PCLXRAW_PROFILE_COUNT
} cf_v2_pclxraw_profile_t;

typedef struct cf_v2_pclxraw_state_s
{
  unsigned int base_profile;
  unsigned int profile_stride_index;
  unsigned int width_index;
  unsigned int height_index;
  unsigned int page_count;
  unsigned int writer_tuple;
  unsigned int compression;
  unsigned int row_schedule;
  unsigned int pattern;
  unsigned int writer_flags;
  unsigned int duplex;
  unsigned int resolution_index;
} cf_v2_pclxraw_state_t;

static const unsigned int cf_v2_pclxraw_profile_strides[] = {
  0U, 1U, 2U, 3U, 5U
};
static const unsigned int cf_v2_pclxraw_widths[] = {
  1U, 7U, 8U, 9U, 15U, 16U, 17U, 31U, 32U, 33U,
  63U, 64U, 65U, 127U, 128U
};
static const unsigned int cf_v2_pclxraw_heights[] = {
  1U, 2U, 3U, 4U, 8U, 16U
};
static const unsigned int cf_v2_pclxraw_resolutions[] = {
  150U, 300U, 600U
};

static void
cf_v2_pclxraw_decode(
    const uint8_t selector[CF_V2_PCLXRAW_SELECTOR_SIZE],
    cf_v2_pclxraw_state_t *state)
{
  state->base_profile = selector[0] % CF_V2_PCLXRAW_PROFILE_COUNT;
  state->profile_stride_index = selector[1] %
      (sizeof(cf_v2_pclxraw_profile_strides) /
       sizeof(cf_v2_pclxraw_profile_strides[0]));
  state->width_index = selector[2] %
      (sizeof(cf_v2_pclxraw_widths) / sizeof(cf_v2_pclxraw_widths[0]));
  state->height_index = selector[3] %
      (sizeof(cf_v2_pclxraw_heights) / sizeof(cf_v2_pclxraw_heights[0]));
  state->page_count = 1U + selector[4] % CF_V2_PCLXRAW_MAX_PAGES;
  state->writer_tuple = selector[5] % 2U;
  state->compression = selector[6] % 3U;
  state->row_schedule = selector[7] % 6U;
  state->pattern = selector[8] % 8U;
  state->writer_flags = selector[9] % 4U;
  state->duplex = selector[10] % 3U;
  state->resolution_index = selector[11] %
      (sizeof(cf_v2_pclxraw_resolutions) /
       sizeof(cf_v2_pclxraw_resolutions[0]));
}

static unsigned int
cf_v2_pclxraw_page_profile(const cf_v2_pclxraw_state_t *state,
                           unsigned int page)
{
  unsigned int stride =
      cf_v2_pclxraw_profile_strides[state->profile_stride_index];

  return (state->base_profile + page * stride) %
         CF_V2_PCLXRAW_PROFILE_COUNT;
}

static unsigned int
cf_v2_pclxraw_width(const cf_v2_pclxraw_state_t *state)
{
  return cf_v2_pclxraw_widths[state->width_index];
}

static unsigned int
cf_v2_pclxraw_height(const cf_v2_pclxraw_state_t *state)
{
  return cf_v2_pclxraw_heights[state->height_index];
}

static unsigned int
cf_v2_pclxraw_resolution(const cf_v2_pclxraw_state_t *state)
{
  return cf_v2_pclxraw_resolutions[state->resolution_index];
}

static unsigned int
cf_v2_pclxraw_profile_planes(unsigned int profile)
{
  switch (profile)
  {
    case CF_V2_PCLXRAW_RGB1 :
    case CF_V2_PCLXRAW_CMY1 :
        return 3U;
    case CF_V2_PCLXRAW_CMYK1 :
        return 4U;
    default :
        return 1U;
  }
}

static int
cf_v2_pclxraw_profile_is_inverse(unsigned int profile)
{
  return profile == CF_V2_PCLXRAW_W1 ||
         profile == CF_V2_PCLXRAW_RGB1;
}

static uint8_t
cf_v2_pclxraw_blank_value(unsigned int profile)
{
  return profile == CF_V2_PCLXRAW_W1 ||
         profile == CF_V2_PCLXRAW_RGB1 ||
         profile == CF_V2_PCLXRAW_RGB24 ? 0xffU : 0x00U;
}

static uint8_t
cf_v2_pclxraw_filter_blank_value(unsigned int profile)
{
  /* Current rastertopclx changes RGB24 BlankValue to 0xff only for mode 10.
   * This target keeps the Raster-semantic 0xff source blank above, but its
   * oracle must model the actual mode 0/1/2 ReadLine predicate. */
  return profile == CF_V2_PCLXRAW_W1 ||
         profile == CF_V2_PCLXRAW_RGB1 ? 0xffU : 0x00U;
}

static size_t
cf_v2_pclxraw_plane_bytes(unsigned int profile, unsigned int width)
{
  return profile == CF_V2_PCLXRAW_RGB24 ? (size_t)width * 3U :
                                         ((size_t)width + 7U) / 8U;
}

static size_t
cf_v2_pclxraw_row_bytes(unsigned int profile, unsigned int width)
{
  size_t plane_bytes = cf_v2_pclxraw_plane_bytes(profile, width);

  return profile == CF_V2_PCLXRAW_RGB24 ? plane_bytes :
      plane_bytes * cf_v2_pclxraw_profile_planes(profile);
}

static int
cf_v2_pclxraw_row_is_data(const cf_v2_pclxraw_state_t *state,
                          unsigned int row, unsigned int height)
{
  switch (state->row_schedule)
  {
    case 0U : return 1; /* all data */
    case 1U : return row == 0U || row + 1U == height; /* first/last */
    case 2U : return (row & 1U) == 0U; /* alternating */
    case 3U : return row == height / 2U; /* middle */
    case 4U : return row >= height / 2U; /* blank to data */
    default : return row < (height + 1U) / 2U; /* data to blank */
  }
}

static uint8_t
cf_v2_pclxraw_material_byte(const uint8_t *material, size_t material_size,
                            unsigned int page, unsigned int row,
                            size_t unit, unsigned int channel)
{
  size_t offset = (size_t)page * 1031U + (size_t)row * 257U +
                  unit * 17U + (size_t)channel * 5U;

  return material[offset % material_size];
}

static uint8_t
cf_v2_pclxraw_pattern_byte(const cf_v2_pclxraw_state_t *state,
                           const uint8_t *material, size_t material_size,
                           unsigned int page, unsigned int row,
                           size_t unit, unsigned int channel)
{
  static const uint8_t cycle[] = {
    0x00U, 0xffU, 0x55U, 0xaaU, 0x11U, 0x80U, 0x7fU, 0xeeU
  };

  switch (state->pattern)
  {
    case 0U :
        return 0x00U;
    case 1U :
        return 0xffU;
    case 2U :
        return ((unit + row + page + channel) & 1U) ? 0xaaU : 0x55U;
    case 3U :
        return (((unit / 2U) + row + channel) & 1U) ? 0xffU : 0x00U;
    case 4U :
        return (uint8_t)((unit * 37U + row * 19U + page * 11U) & 0xffU);
    case 5U :
        return (uint8_t)(0x21U + channel * 0x35U +
                         (unsigned int)(unit & 7U));
    case 6U :
        return cycle[(unit + 3U * channel + row + page) %
                     (sizeof(cycle) / sizeof(cycle[0]))];
    default :
        return cf_v2_pclxraw_material_byte(material, material_size, page, row,
                                           unit, channel);
  }
}

static int
cf_v2_pclxraw_all_value(const uint8_t *data, size_t size, uint8_t value)
{
  size_t index;

  for (index = 0U; index < size; index ++)
    if (data[index] != value)
      return 0;
  return 1;
}

static void
cf_v2_pclxraw_build_row(uint8_t *line, size_t line_size,
                        const cf_v2_pclxraw_state_t *state,
                        const uint8_t *material, size_t material_size,
                        unsigned int page, unsigned int row,
                        unsigned int profile, unsigned int width,
                        int data_row)
{
  uint8_t blank = cf_v2_pclxraw_blank_value(profile);
  size_t row_bytes = cf_v2_pclxraw_row_bytes(profile, width);
  size_t index;

  if (!line || row_bytes > line_size)
    return;
  if (!data_row)
  {
    memset(line, blank, row_bytes);
    return;
  }

  if (profile == CF_V2_PCLXRAW_RGB24)
  {
    for (index = 0U; index < row_bytes; index ++)
      line[index] = cf_v2_pclxraw_pattern_byte(
          state, material, material_size, page, row, index / 3U,
          (unsigned int)(index % 3U));
  }
  else
  {
    size_t plane_bytes = cf_v2_pclxraw_plane_bytes(profile, width);
    unsigned int plane;

    for (plane = 0U; plane < cf_v2_pclxraw_profile_planes(profile); plane ++)
      for (index = 0U; index < plane_bytes; index ++)
        line[(size_t)plane * plane_bytes + index] =
            cf_v2_pclxraw_pattern_byte(
                state, material, material_size, page, row, index, plane);
  }

  /* Keep scheduled data rows distinguishable from each profile's blank row. */
  if (cf_v2_pclxraw_all_value(line, row_bytes, blank))
    line[0] = (uint8_t)(blank ^ 0x80U);
  if (cf_v2_pclxraw_all_value(
          line, row_bytes, cf_v2_pclxraw_filter_blank_value(profile)))
    line[0] ^= 0x40U;
}

static size_t
cf_v2_pclxraw_find(const uint8_t *data, size_t size, size_t start,
                   const uint8_t *needle, size_t needle_size)
{
  size_t position;

  if (!needle_size || start > size || needle_size > size - start)
    return SIZE_MAX;
  for (position = start; position <= size - needle_size; position ++)
    if (memcmp(data + position, needle, needle_size) == 0)
      return position;
  return SIZE_MAX;
}

static size_t
cf_v2_pclxraw_count_span(const uint8_t *data, size_t begin, size_t end,
                         const uint8_t *needle, size_t needle_size)
{
  size_t count = 0U;
  size_t position = begin;

  if (begin > end || !needle_size)
    return 0U;
  while (position <= end && needle_size <= end - position)
  {
    size_t found = cf_v2_pclxraw_find(data, end, position,
                                     needle, needle_size);

    if (found == SIZE_MAX)
      break;
    count ++;
    position = found + needle_size;
  }
  return count;
}

static int
cf_v2_pclxraw_take(const uint8_t *capture, size_t capture_size,
                   size_t *position, const uint8_t *expected,
                   size_t expected_size)
{
  if (!position || *position > capture_size ||
      expected_size > capture_size - *position ||
      memcmp(capture + *position, expected, expected_size) != 0)
    return 0;
  *position += expected_size;
  return 1;
}

typedef struct cf_v2_pclxraw_transfer_s
{
  const uint8_t *payload;
  size_t payload_size;
  uint8_t terminator;
} cf_v2_pclxraw_transfer_t;

static int
cf_v2_pclxraw_parse_transfer(const uint8_t *capture, size_t capture_size,
                             size_t *position,
                             cf_v2_pclxraw_transfer_t *transfer)
{
  size_t cursor;
  size_t length = 0U;
  int have_digit = 0;

  if (!capture || !position || !transfer)
    return 0;
  cursor = *position;
  if (cursor + 5U > capture_size || capture[cursor] != 0x1bU ||
      capture[cursor + 1U] != '*' || capture[cursor + 2U] != 'b')
    return 0;
  cursor += 3U;
  while (cursor < capture_size && capture[cursor] >= '0' &&
         capture[cursor] <= '9')
  {
    size_t digit = (size_t)(capture[cursor] - '0');

    if (length > (CF_V2_PCLXRAW_MAX_CAPTURE - digit) / 10U)
      return 0;
    length = length * 10U + digit;
    have_digit = 1;
    cursor ++;
  }
  if (!have_digit || cursor >= capture_size ||
      (capture[cursor] != 'V' && capture[cursor] != 'W') ||
      length > capture_size - cursor - 1U)
    return 0;
  transfer->terminator = capture[cursor ++];
  transfer->payload = capture + cursor;
  transfer->payload_size = length;
  *position = cursor + length;
  return 1;
}

static int
cf_v2_pclxraw_decode_mode0(const cf_v2_pclxraw_transfer_t *transfer,
                           uint8_t *decoded, size_t expected_size)
{
  if (transfer->payload_size == expected_size)
  {
    memcpy(decoded, transfer->payload, expected_size);
    return 1;
  }
  if (transfer->payload_size == 0U)
  {
    memset(decoded, 0, expected_size);
    return 1;
  }
  return 0;
}

static int
cf_v2_pclxraw_decode_mode1(const cf_v2_pclxraw_transfer_t *transfer,
                           uint8_t *decoded, size_t expected_size)
{
  size_t input = 0U;
  size_t output = 0U;

  while (input < transfer->payload_size)
  {
    size_t count;
    uint8_t value;

    if (transfer->payload_size - input < 2U)
      return 0;
    count = (size_t)transfer->payload[input] + 1U;
    value = transfer->payload[input + 1U];
    input += 2U;
    if (count > expected_size - output)
      return 0;
    memset(decoded + output, value, count);
    output += count;
  }
  return output == expected_size;
}

static int
cf_v2_pclxraw_decode_mode2(const cf_v2_pclxraw_transfer_t *transfer,
                           uint8_t *decoded, size_t expected_size)
{
  size_t input = 0U;
  size_t output = 0U;

  while (input < transfer->payload_size)
  {
    uint8_t control = transfer->payload[input ++];

    if (control <= 127U)
    {
      size_t count = (size_t)control + 1U;

      if (count > transfer->payload_size - input ||
          count > expected_size - output)
        return 0;
      memcpy(decoded + output, transfer->payload + input, count);
      input += count;
      output += count;
    }
    else if (control >= 129U)
    {
      size_t count = 257U - (size_t)control;

      if (input >= transfer->payload_size || count > expected_size - output)
        return 0;
      memset(decoded + output, transfer->payload[input ++], count);
      output += count;
    }
    else
      return 0; /* 128 is the PackBits no-op and is never emitted here. */
  }
  return output == expected_size;
}

static int
cf_v2_pclxraw_validate_plane(const cf_v2_pclxraw_transfer_t *transfer,
                             unsigned int compression,
                             const uint8_t *expected, size_t expected_size)
{
  uint8_t decoded[CF_V2_PCLXRAW_MAX_ROW_BYTES];
  int ok;

  if (!expected || expected_size > sizeof(decoded))
    return 0;
  switch (compression)
  {
    case 0U :
        ok = cf_v2_pclxraw_decode_mode0(transfer, decoded, expected_size);
        break;
    case 1U :
        ok = cf_v2_pclxraw_decode_mode1(transfer, decoded, expected_size);
        break;
    case 2U :
        ok = cf_v2_pclxraw_decode_mode2(transfer, decoded, expected_size);
        break;
    default :
        return 0;
  }
  return ok && memcmp(decoded, expected, expected_size) == 0;
}

static int
cf_v2_pclxraw_validate_setup(const uint8_t *capture, size_t begin,
                             size_t end, const cf_v2_pclxraw_state_t *state,
                             unsigned int page, unsigned int profile)
{
  static const uint8_t cid[] = {
    0x1bU, '*', 'v', '6', 'W', 2U, 3U, 0U, 8U, 8U, 8U
  };
  static const uint8_t simple_cmy[] = {0x1bU, '*', 'r', '-', '3', 'U'};
  static const uint8_t simple_kcmy[] = {0x1bU, '*', 'r', '-', '4', 'U'};
  static const uint8_t backside[] = {0x1bU, '&', 'a', '2', 'G'};
  static const uint8_t reset[] = {0x1bU, 'E'};
  static const uint8_t crd_prefix[] = {0x1bU, '*', 'g'};
  static const uint8_t pjl_prefix[] = {'@', 'P', 'J', 'L'};
  char resolution[32];
  int resolution_size;
  size_t expected_cmy = 0U;
  size_t expected_kcmy = 0U;
  size_t expected_cid = 0U;
  size_t expected_backside = 0U;

  if (begin > end)
    return 0;
  resolution_size = snprintf(resolution, sizeof(resolution), "\033*t%uR",
                             cf_v2_pclxraw_resolution(state));
  if (resolution_size <= 0 || (size_t)resolution_size >= sizeof(resolution))
    return 0;

  if (profile == CF_V2_PCLXRAW_RGB1 ||
      profile == CF_V2_PCLXRAW_CMY1 ||
      (profile == CF_V2_PCLXRAW_RGB24 && state->writer_tuple == 0U))
    expected_cmy = 1U;
  else if (profile == CF_V2_PCLXRAW_CMYK1)
    expected_kcmy = 1U;
  else if (profile == CF_V2_PCLXRAW_RGB24 && state->writer_tuple == 1U)
    expected_cid = 1U;
  if (state->duplex && ((page + 1U) & 1U) == 0U)
    expected_backside = 1U;

  return cf_v2_pclxraw_count_span(
             capture, begin, end, (const uint8_t *)resolution,
             (size_t)resolution_size) == 1U &&
         cf_v2_pclxraw_count_span(capture, begin, end, cid,
                                  sizeof(cid)) == expected_cid &&
         cf_v2_pclxraw_count_span(capture, begin, end, simple_cmy,
                                  sizeof(simple_cmy)) == expected_cmy &&
         cf_v2_pclxraw_count_span(capture, begin, end, simple_kcmy,
                                  sizeof(simple_kcmy)) == expected_kcmy &&
         cf_v2_pclxraw_count_span(capture, begin, end, backside,
                                  sizeof(backside)) == expected_backside &&
         cf_v2_pclxraw_count_span(capture, begin, end, reset,
                                  sizeof(reset)) == 0U &&
         cf_v2_pclxraw_count_span(capture, begin, end, crd_prefix,
                                  sizeof(crd_prefix)) == 0U &&
         cf_v2_pclxraw_count_span(capture, begin, end, pjl_prefix,
                                  sizeof(pjl_prefix)) == 0U;
}

static int
cf_v2_pclxraw_validate_output(const uint8_t *capture, size_t capture_size,
                              const cf_v2_pclxraw_state_t *state,
                              const uint8_t *material, size_t material_size)
{
  static const uint8_t uel[] = {
    0x1bU, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L',
    '\r', '\n'
  };
  static const uint8_t pjl_job[] = {
    '@', 'P', 'J', 'L', ' ', 'J', 'O', 'B', ' ', 'N', 'A', 'M', 'E', ' ',
    '=', ' ', '"', 'P', 'C', 'L', 'X', 'R', 'A', 'W', '1', '"', ' ',
    'D', 'I', 'S', 'P', 'L', 'A', 'Y', ' ', '=', ' ', '"', '1', ' ',
    'l', 'i', 'b', 'f', 'u', 'z', 'z', 'e', 'r', ' ', 'P', 'C', 'L',
    'X', 'R', 'A', 'W', '1', '"', '\r', '\n'
  };
  static const uint8_t pjl_enter[] = {
    '@', 'P', 'J', 'L', ' ', 'E', 'N', 'T', 'E', 'R', ' ', 'L', 'A', 'N',
    'G', 'U', 'A', 'G', 'E', '=', 'P', 'C', 'L', '\r', '\n'
  };
  static const uint8_t pjl_eoj[] = {
    '@', 'P', 'J', 'L', ' ', 'E', 'O', 'J', '\r', '\n'
  };
  static const uint8_t reset[] = {0x1bU, 'E'};
  static const uint8_t end_color[] = {0x1bU, '*', 'r', 'C'};
  static const uint8_t end_mono[] = {0x1bU, '*', 'r', '0', 'B'};
  size_t position = 0U;
  unsigned int page;
  unsigned int width;
  unsigned int height;

  if (!capture || !state || !material || !material_size ||
      !capture_size || capture_size > CF_V2_PCLXRAW_MAX_CAPTURE)
    return 0;
  width = cf_v2_pclxraw_width(state);
  height = cf_v2_pclxraw_height(state);

  if (state->writer_flags & CF_V2_PCLXRAW_PJL)
  {
    if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                            uel, sizeof(uel)) ||
        !cf_v2_pclxraw_take(capture, capture_size, &position,
                            pjl_job, sizeof(pjl_job)) ||
        !cf_v2_pclxraw_take(capture, capture_size, &position,
                            pjl_enter, sizeof(pjl_enter)))
      return 0;
  }
  if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                          reset, sizeof(reset)))
    return 0;

  for (page = 0U; page < state->page_count; page ++)
  {
    unsigned int profile = cf_v2_pclxraw_page_profile(state, page);
    unsigned int planes = cf_v2_pclxraw_profile_planes(profile);
    size_t plane_bytes = cf_v2_pclxraw_plane_bytes(profile, width);
    size_t row_bytes = cf_v2_pclxraw_row_bytes(profile, width);
    size_t setup_begin = position;
    size_t geometry_position;
    char geometry[64];
    int geometry_size;
    unsigned int row;
    unsigned int pending_blank = 0U;
    uint8_t source[CF_V2_PCLXRAW_MAX_ROW_BYTES];

    geometry_size = snprintf(geometry, sizeof(geometry),
                             "\033*r%uS\033*r%uT\033*r1A", width, height);
    if (geometry_size <= 0 || (size_t)geometry_size >= sizeof(geometry))
      return 0;
    geometry_position = cf_v2_pclxraw_find(
        capture, capture_size, position, (const uint8_t *)geometry,
        (size_t)geometry_size);
    if (geometry_position == SIZE_MAX ||
        !cf_v2_pclxraw_validate_setup(capture, setup_begin,
                                      geometry_position, state, page,
                                      profile))
      return 0;
    position = geometry_position + (size_t)geometry_size;

    if (state->compression != 0U)
    {
      char command[16];
      int command_size = snprintf(command, sizeof(command), "\033*b%uM",
                                  state->compression);

      if (command_size <= 0 || (size_t)command_size >= sizeof(command) ||
          !cf_v2_pclxraw_take(capture, capture_size, &position,
                              (const uint8_t *)command,
                              (size_t)command_size))
        return 0;
    }
    else
    {
      static const uint8_t mode_prefix[] = {0x1bU, '*', 'b', '0', 'M'};

      if (cf_v2_pclxraw_find(capture, capture_size, position,
                             mode_prefix, sizeof(mode_prefix)) == position)
        return 0;
    }

    for (row = 0U; row < height; row ++)
    {
      unsigned int plane;
      int scheduled_data =
          cf_v2_pclxraw_row_is_data(state, row, height);

      cf_v2_pclxraw_build_row(source, sizeof(source), state, material,
                              material_size, page, row, profile, width,
                              scheduled_data);
      if (cf_v2_pclxraw_all_value(
              source, row_bytes,
              cf_v2_pclxraw_filter_blank_value(profile)))
      {
        pending_blank ++;
        continue;
      }

      while (pending_blank > 0U)
      {
        cf_v2_pclxraw_transfer_t transfer;

        if (!cf_v2_pclxraw_parse_transfer(capture, capture_size, &position,
                                           &transfer) ||
            transfer.terminator != 'W' || transfer.payload_size != 0U)
          return 0;
        pending_blank --;
      }

      for (plane = 0U; plane < planes; plane ++)
      {
        cf_v2_pclxraw_transfer_t transfer;
        uint8_t expected[CF_V2_PCLXRAW_MAX_ROW_BYTES];
        const uint8_t *plane_source = source + (size_t)plane * plane_bytes;
        size_t index;
        uint8_t expected_terminator = plane + 1U == planes ? 'W' : 'V';

        if (profile == CF_V2_PCLXRAW_RGB24)
          plane_source = source;
        for (index = 0U; index < plane_bytes; index ++)
          expected[index] = cf_v2_pclxraw_profile_is_inverse(profile) ?
              (uint8_t)~plane_source[index] : plane_source[index];
        if (!cf_v2_pclxraw_parse_transfer(capture, capture_size, &position,
                                           &transfer) ||
            transfer.terminator != expected_terminator ||
            !cf_v2_pclxraw_validate_plane(
                &transfer, state->compression, expected, plane_bytes))
          return 0;
      }
    }

    if (state->writer_flags & CF_V2_PCLXRAW_END_COLOR)
    {
      if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                              end_color, sizeof(end_color)))
        return 0;
    }
    else if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                                 end_mono, sizeof(end_mono)))
      return 0;

    if (!state->duplex || ((page + 1U) & 1U) == 0U)
    {
      static const uint8_t form_feed[] = {'\f'};

      if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                              form_feed, sizeof(form_feed)))
        return 0;
    }
    else if (position < capture_size && capture[position] == '\f')
      return 0;
  }

  if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                          reset, sizeof(reset)))
    return 0;
  if (state->writer_flags & CF_V2_PCLXRAW_PJL)
  {
    if (!cf_v2_pclxraw_take(capture, capture_size, &position,
                            uel, sizeof(uel)) ||
        !cf_v2_pclxraw_take(capture, capture_size, &position,
                            pjl_eoj, sizeof(pjl_eoj)) ||
        !cf_v2_pclxraw_take(capture, capture_size, &position,
                            uel, sizeof(uel)))
      return 0;
  }
  return position == capture_size;
}

int
cf_v2_pclxraw_validate_capture_for_test(
    const uint8_t *capture, size_t capture_size,
    const uint8_t *selector, size_t selector_size,
    const uint8_t *material, size_t material_size)
{
  cf_v2_pclxraw_state_t state;

  if (!selector || selector_size != CF_V2_PCLXRAW_SELECTOR_SIZE ||
      !material || material_size < CF_V2_PCLXRAW_MIN_MATERIAL ||
      material_size > CF_V2_PCLXRAW_MAX_MATERIAL)
    return 0;
  cf_v2_pclxraw_decode(selector, &state);
  return cf_v2_pclxraw_validate_output(capture, capture_size, &state,
                                       material, material_size);
}

#ifndef CF_V2_PCLXRAW_ORACLE_ONLY

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/colormanager.h>
#include <cupsfilters/driver.h>
#include <cupsfilters/filter.h>
#include <fcntl.h>
#include <ppd/ppd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef CF_V2_RASTERTOPCLX_SOURCE
#error "CF_V2_RASTERTOPCLX_SOURCE must quote filter/rastertopclx.c"
#endif
#ifndef CF_V2_PCL_COMMON_SOURCE
#error "CF_V2_PCL_COMMON_SOURCE must quote filter/pcl-common.c"
#endif

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint8_t cf_v2_pclxraw_capture[CF_V2_PCLXRAW_MAX_CAPTURE];
static size_t cf_v2_pclxraw_capture_size;
static ppd_file_t *cf_v2_pclxraw_filter_ppd;
static unsigned int cf_v2_pclxraw_page_log_count;
static int cf_v2_pclxraw_page_logs[CF_V2_PCLXRAW_MAX_PAGES];
static char cf_v2_pclxraw_ppd_env[
    sizeof("PPD=/tmp/pclxraw1-XXXXXX/input.ppd")];
static char cf_v2_pclxraw_printer_env[] = "PRINTER=pclxraw1";
static char cf_v2_pclxraw_content_type_env[] =
    "CONTENT_TYPE=application/vnd.cups-raster";
static int cf_v2_pclxraw_environment_installed;

static void
cf_v2_pclxraw_require(int condition)
{
  if (!condition)
    __builtin_trap();
}

static size_t
cf_v2_pclxraw_capture_bytes(const void *data, size_t size)
{
  cf_v2_pclxraw_require(size <=
      CF_V2_PCLXRAW_MAX_CAPTURE - cf_v2_pclxraw_capture_size);
  memcpy(cf_v2_pclxraw_capture + cf_v2_pclxraw_capture_size, data, size);
  cf_v2_pclxraw_capture_size += size;
  return size;
}

static int
cf_v2_pclxraw_capture_putchar(int value)
{
  uint8_t byte = (uint8_t)value;

  (void)cf_v2_pclxraw_capture_bytes(&byte, 1U);
  return byte;
}

static int
cf_v2_pclxraw_capture_printf(const char *format, ...)
{
  char buffer[512];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  cf_v2_pclxraw_require(result >= 0 && (size_t)result < sizeof(buffer));
  (void)cf_v2_pclxraw_capture_bytes(buffer, (size_t)result);
  return result;
}

static int
cf_v2_pclxraw_capture_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;

  va_start(arguments, format);
  if (stream == stdout)
  {
    char buffer[512];
    int result = vsnprintf(buffer, sizeof(buffer), format, arguments);

    va_end(arguments);
    cf_v2_pclxraw_require(result >= 0 && (size_t)result < sizeof(buffer));
    (void)cf_v2_pclxraw_capture_bytes(buffer, (size_t)result);
    return result;
  }
  if (strcmp(format, "PAGE: %d %d\n") == 0)
  {
    int page = va_arg(arguments, int);
    int copies = va_arg(arguments, int);

    if (cf_v2_pclxraw_page_log_count < CF_V2_PCLXRAW_MAX_PAGES &&
        copies == 1)
      cf_v2_pclxraw_page_logs[cf_v2_pclxraw_page_log_count ++] = page;
  }
  va_end(arguments);
  return 0;
}

static int
cf_v2_pclxraw_capture_fputs(const char *text, FILE *stream)
{
  if (stream == stdout)
  {
    (void)cf_v2_pclxraw_capture_bytes(text, strlen(text));
    return 0;
  }
  return 0;
}

static void
cf_v2_pclxraw_quiet_log(void *data, cf_loglevel_t level,
                        const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static ppd_file_t *
cf_v2_pclxraw_ppd_open(const char *path)
{
  cf_v2_pclxraw_filter_ppd = ppdOpenFile(path);
  return cf_v2_pclxraw_filter_ppd;
}

static cf_cm_calibration_t
cf_v2_pclxraw_calibration_mode(cf_filter_data_t *data)
{
  (void)data;
  return CF_CM_CALIBRATION_DISABLED;
}

static int
cf_v2_pclxraw_color_management_disabled(cf_filter_data_t *data)
{
  (void)data;
  return 0;
}

static void
cf_v2_pclxraw_ignore_setbuf(FILE *stream, char *buffer)
{
  (void)stream;
  (void)buffer;
}

#undef cfWritePrintData
#define cfWritePrintData(data, size) \
  cf_v2_pclxraw_capture_bytes((data), (size_t)(size))
#define putchar cf_v2_pclxraw_capture_putchar
#define printf cf_v2_pclxraw_capture_printf
#define fprintf cf_v2_pclxraw_capture_fprintf
#define fputs cf_v2_pclxraw_capture_fputs
#define cfCUPSLogFunc cf_v2_pclxraw_quiet_log
#define ppdOpenFile cf_v2_pclxraw_ppd_open
#define cfCmGetCupsColorCalibrateMode cf_v2_pclxraw_calibration_mode
#define cfCmIsPrinterCmDisabled cf_v2_pclxraw_color_management_disabled
#define setbuf cf_v2_pclxraw_ignore_setbuf
#define main cf_v2_pclxraw_rastertopclx_main
#include CF_V2_RASTERTOPCLX_SOURCE
#undef main
#include CF_V2_PCL_COMMON_SOURCE
#undef setbuf
#undef cfCmIsPrinterCmDisabled
#undef cfCmGetCupsColorCalibrateMode
#undef ppdOpenFile
#undef cfCUPSLogFunc
#undef fputs
#undef fprintf
#undef printf
#undef putchar
#undef cfWritePrintData

static unsigned int
cf_v2_pclxraw_model_number(const cf_v2_pclxraw_state_t *state)
{
  unsigned int model = PCL_RASTER_SIMPLE | PCL_RASTER_RGB24;

  if (state->writer_tuple == 1U)
    model |= PCL_RASTER_CID;
  if (state->writer_flags & CF_V2_PCLXRAW_END_COLOR)
    model |= PCL_RASTER_END_COLOR;
  if (state->writer_flags & CF_V2_PCLXRAW_PJL)
    model |= PCL_PJL;
  return model;
}

static int
cf_v2_pclxraw_write_ppd(const char *path,
                        const cf_v2_pclxraw_state_t *state)
{
  FILE *file = fopen(path, "w");
  int result;

  if (!file)
    return 0;
  result = fprintf(
      file,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"1.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"PCLXRAW1 raw plane writer\"\n"
      "*ShortNickName: \"PCLXRAW1\"\n"
      "*NickName: \"PCLXRAW1 raw plane writer lifecycle\"\n"
      "*PCFileName: \"PCLXRAW.PPD\"\n"
      "*Product: \"(PCLXRAW1)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 1.0\n"
      "*cupsModelNumber: %u\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 rastertopclx\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Letter\n"
      "*PageSize Letter/Letter: "
      "\"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*OpenUI *PageRegion/Page Region: PickOne\n"
      "*DefaultPageRegion: Letter\n"
      "*PageRegion Letter/Letter: "
      "\"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageRegion\n"
      "*DefaultImageableArea: Letter\n"
      "*ImageableArea Letter/Letter: \"18 36 594 756\"\n"
      "*DefaultPaperDimension: Letter\n"
      "*PaperDimension Letter/Letter: \"612 792\"\n"
      "*OpenUI *ColorModel/Color Model: PickOne\n"
      "*DefaultColorModel: RGB\n"
      "*ColorModel RGB/RGB: "
      "\"<</cupsColorSpace 1/cupsColorOrder 0/cupsBitsPerColor 8/"
      "cupsBitsPerPixel 24>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *MediaType/Media Type: PickOne\n"
      "*DefaultMediaType: Plain\n"
      "*MediaType Plain/Plain: \"<</MediaType(PLAIN)>>setpagedevice\"\n"
      "*CloseUI: *MediaType\n"
      "*OpenUI *Resolution/Resolution: PickOne\n"
      "*DefaultResolution: 300dpi\n"
      "*Resolution 150dpi/150 dpi: "
      "\"<</HWResolution[150 150]>>setpagedevice\"\n"
      "*Resolution 300dpi/300 dpi: "
      "\"<</HWResolution[300 300]>>setpagedevice\"\n"
      "*Resolution 600dpi/600 dpi: "
      "\"<</HWResolution[600 600]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n",
      cf_v2_pclxraw_model_number(state));
  if (fclose(file) != 0)
    return 0;
  return result >= 0;
}

static int
cf_v2_pclxraw_verify_ppd(const char *path,
                         const cf_v2_pclxraw_state_t *state)
{
  ppd_file_t *ppd = ppdOpenFile(path);
  int ok = 0;

  if (!ppd)
    return 0;
  if ((unsigned int)ppd->model_number ==
          cf_v2_pclxraw_model_number(state) &&
      ppdFindAttr(ppd, "cupsPCL", "EndJob") == NULL)
    ok = 1;
  ppdClose(ppd);
  return ok;
}

static void
cf_v2_pclxraw_fill_header(cups_page_header2_t *header,
                          const cf_v2_pclxraw_state_t *state,
                          unsigned int profile)
{
  unsigned int width = cf_v2_pclxraw_width(state);
  unsigned int height = cf_v2_pclxraw_height(state);
  unsigned int resolution = cf_v2_pclxraw_resolution(state);
  unsigned int planes = cf_v2_pclxraw_profile_planes(profile);

  memset(header, 0, sizeof(*header));
  memcpy(header->MediaClass, "PwgRaster", sizeof("PwgRaster"));
  memcpy(header->MediaType, "PLAIN", sizeof("PLAIN"));
  memcpy(header->cupsPageSizeName, "Letter", sizeof("Letter"));
  header->HWResolution[0] = resolution;
  header->HWResolution[1] = resolution;
  header->PageSize[0] = 612U;
  header->PageSize[1] = 792U;
  header->cupsPageSize[0] = 612.0f;
  header->cupsPageSize[1] = 792.0f;
  header->ImagingBoundingBox[2] = 612U;
  header->ImagingBoundingBox[3] = 792U;
  header->cupsImagingBBox[2] = 612.0f;
  header->cupsImagingBBox[3] = 792.0f;
  header->cupsWidth = width;
  header->cupsHeight = height;
  header->cupsCompression = state->compression;
  header->cupsRowCount = 1U;
  header->cupsRowFeed = 1U;
  header->cupsRowStep = 1U;
  header->cupsNumColors = planes;
  header->NumCopies = 1U;
  header->Duplex = state->duplex != 0U;
  header->Tumble = state->duplex == 2U;

  switch (profile)
  {
    case CF_V2_PCLXRAW_K1 :
        header->cupsBitsPerColor = 1U;
        header->cupsBitsPerPixel = 1U;
        header->cupsBytesPerLine = (width + 7U) / 8U;
        header->cupsColorOrder = CUPS_ORDER_BANDED;
        header->cupsColorSpace = CUPS_CSPACE_K;
        break;
    case CF_V2_PCLXRAW_W1 :
        header->cupsBitsPerColor = 1U;
        header->cupsBitsPerPixel = 1U;
        header->cupsBytesPerLine = (width + 7U) / 8U;
        header->cupsColorOrder = CUPS_ORDER_BANDED;
        header->cupsColorSpace = CUPS_CSPACE_W;
        break;
    case CF_V2_PCLXRAW_RGB1 :
        header->cupsBitsPerColor = 1U;
        header->cupsBitsPerPixel = 1U;
        header->cupsBytesPerLine = ((width + 7U) / 8U) * 3U;
        header->cupsColorOrder = CUPS_ORDER_BANDED;
        header->cupsColorSpace = CUPS_CSPACE_RGB;
        break;
    case CF_V2_PCLXRAW_CMY1 :
        header->cupsBitsPerColor = 1U;
        header->cupsBitsPerPixel = 1U;
        header->cupsBytesPerLine = ((width + 7U) / 8U) * 3U;
        header->cupsColorOrder = CUPS_ORDER_BANDED;
        header->cupsColorSpace = CUPS_CSPACE_CMY;
        break;
    case CF_V2_PCLXRAW_CMYK1 :
        header->cupsBitsPerColor = 1U;
        header->cupsBitsPerPixel = 1U;
        header->cupsBytesPerLine = ((width + 7U) / 8U) * 4U;
        header->cupsColorOrder = CUPS_ORDER_BANDED;
        header->cupsColorSpace = CUPS_CSPACE_CMYK;
        break;
    default :
        header->cupsBitsPerColor = 8U;
        header->cupsBitsPerPixel = 24U;
        header->cupsBytesPerLine = width * 3U;
        header->cupsColorOrder = CUPS_ORDER_CHUNKED;
        header->cupsColorSpace = CUPS_CSPACE_RGB;
        header->cupsNumColors = 3U;
        break;
  }
}

static int
cf_v2_pclxraw_write_raster(const char *path,
                           const cf_v2_pclxraw_state_t *state,
                           const uint8_t *material, size_t material_size)
{
  cups_raster_t *raster = NULL;
  uint8_t line[CF_V2_PCLXRAW_MAX_ROW_BYTES];
  int descriptor = -1;
  int ok = 0;
  unsigned int page;

  descriptor = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (descriptor < 0)
    return 0;
  raster = cupsRasterOpen(descriptor, CUPS_RASTER_WRITE);
  if (!raster)
    goto done;

  for (page = 0U; page < state->page_count; page ++)
  {
    cups_page_header2_t header;
    unsigned int profile = cf_v2_pclxraw_page_profile(state, page);
    unsigned int height = cf_v2_pclxraw_height(state);
    unsigned int row;

    cf_v2_pclxraw_fill_header(&header, state, profile);
    if (!cupsRasterWriteHeader2(raster, &header))
      goto done;
    for (row = 0U; row < height; row ++)
    {
      cf_v2_pclxraw_build_row(
          line, sizeof(line), state, material, material_size, page, row,
          profile, cf_v2_pclxraw_width(state),
          cf_v2_pclxraw_row_is_data(state, row, height));
      if (cupsRasterWritePixels(raster, line, header.cupsBytesPerLine) !=
          header.cupsBytesPerLine)
        goto done;
    }
  }
  ok = 1;

done:
  if (raster)
    cupsRasterClose(raster);
  if (descriptor >= 0)
    close(descriptor);
  return ok;
}

static int
cf_v2_pclxraw_install_environment(const char *ppd_path)
{
  int length = snprintf(cf_v2_pclxraw_ppd_env,
                        sizeof(cf_v2_pclxraw_ppd_env), "PPD=%s", ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_pclxraw_ppd_env))
    return 0;
  if (cf_v2_pclxraw_environment_installed)
    return 1;
  if (putenv(cf_v2_pclxraw_ppd_env) != 0 ||
      putenv(cf_v2_pclxraw_printer_env) != 0 ||
      putenv(cf_v2_pclxraw_content_type_env) != 0)
    return 0;
  cf_v2_pclxraw_environment_installed = 1;
  return 1;
}

static void
cf_v2_pclxraw_reset_filter_globals(void)
{
  RGB = NULL;
  CMYK = NULL;
  PixelBuffer = NULL;
  CMYKBuffer = NULL;
  InputBuffer = NULL;
  CompBuffer = NULL;
  SeedBuffer = NULL;
  memset(OutputBuffers, 0, sizeof(OutputBuffers));
  memset(DotBuffers, 0, sizeof(DotBuffers));
  memset(DitherLuts, 0, sizeof(DitherLuts));
  memset(DitherStates, 0, sizeof(DitherStates));
  memset(DotBits, 0, sizeof(DotBits));
  memset(DotBufferSizes, 0, sizeof(DotBufferSizes));
  BlankValue = 0U;
  PrinterPlanes = 0;
  SeedInvalid = 0;
  DotBufferSize = 0;
  OutputFeed = 0;
  Page = 0;
  Canceled = 0;
  OutputMode = OUTPUT_BITMAP;
  logfunc = NULL;
  ld = NULL;
}

static int
cf_v2_pclxraw_run_filter(const char *ppd_path, const char *raster_path,
                         const cf_v2_pclxraw_state_t *state,
                         const uint8_t *material, size_t material_size)
{
  char options[192];
  char *arguments[] = {
    (char *)"rastertopclx", (char *)"1", (char *)"libfuzzer",
    (char *)"PCLXRAW1", (char *)"1", options, (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  int have_saved_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  unsigned int page;
  int status;
  int ok = 0;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=RGB MediaType=Plain "
           "Resolution=%udpi emit-jcl=false",
           cf_v2_pclxraw_resolution(state));
  if (!cf_v2_pclxraw_install_environment(ppd_path))
    goto done;

  cf_v2_pclxraw_capture_size = 0U;
  cf_v2_pclxraw_filter_ppd = NULL;
  cf_v2_pclxraw_page_log_count = 0U;
  memset(cf_v2_pclxraw_page_logs, 0, sizeof(cf_v2_pclxraw_page_logs));
  status = cf_v2_pclxraw_rastertopclx_main(7, arguments);
  cf_v2_pclxraw_require(status == 0 && cf_v2_pclxraw_filter_ppd != NULL &&
                        cf_v2_pclxraw_page_log_count == state->page_count);
  for (page = 0U; page < state->page_count; page ++)
    cf_v2_pclxraw_require(cf_v2_pclxraw_page_logs[page] == (int)page + 1);
  cf_v2_pclxraw_require(cf_v2_pclxraw_validate_output(
      cf_v2_pclxraw_capture, cf_v2_pclxraw_capture_size, state,
      material, material_size));
  ok = 1;

done:
  if (cf_v2_pclxraw_filter_ppd)
  {
    ppdClose(cf_v2_pclxraw_filter_ppd);
    cf_v2_pclxraw_filter_ppd = NULL;
  }
  cf_v2_pclxraw_reset_filter_globals();
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return ok;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t minimum =
      CF_V2_PCLXRAW_HEADER_SIZE + CF_V2_PCLXRAW_MIN_MATERIAL;
  const size_t maximum =
      CF_V2_PCLXRAW_HEADER_SIZE + CF_V2_PCLXRAW_MAX_MATERIAL;
  const size_t limit = max_size < maximum ? max_size : maximum;
  size_t material_size;

  if (!data || limit < minimum)
    return 0U;
  if (size > limit)
    size = limit;
  if (size < minimum)
  {
    memset(data + size, 0, minimum - size);
    size = minimum;
  }
  memcpy(data, CF_V2_PCLXRAW_MAGIC, CF_V2_PCLXRAW_MAGIC_SIZE);

  if ((seed & 3U) != 0U)
  {
    size_t slot = CF_V2_PCLXRAW_MAGIC_SIZE +
                  ((seed >> 2U) % CF_V2_PCLXRAW_SELECTOR_SIZE);
    uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      data[slot] ^= delta;
    else
      data[slot] += delta;
    return size;
  }

  material_size = LLVMFuzzerMutate(data + CF_V2_PCLXRAW_HEADER_SIZE,
                                   size - CF_V2_PCLXRAW_HEADER_SIZE,
                                   limit - CF_V2_PCLXRAW_HEADER_SIZE);
  if (material_size < CF_V2_PCLXRAW_MIN_MATERIAL)
  {
    data[CF_V2_PCLXRAW_HEADER_SIZE] = (uint8_t)seed;
    material_size = CF_V2_PCLXRAW_MIN_MATERIAL;
  }
  if (material_size > CF_V2_PCLXRAW_MAX_MATERIAL)
    material_size = CF_V2_PCLXRAW_MAX_MATERIAL;
  memcpy(data, CF_V2_PCLXRAW_MAGIC, CF_V2_PCLXRAW_MAGIC_SIZE);
  return CF_V2_PCLXRAW_HEADER_SIZE + material_size;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/pclxraw1-XXXXXX";
  char ppd_path[sizeof(directory) + 16U];
  char raster_path[sizeof(directory) + 16U];
  cf_v2_pclxraw_state_t state;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;

  if (!data ||
      size < CF_V2_PCLXRAW_HEADER_SIZE + CF_V2_PCLXRAW_MIN_MATERIAL ||
      size > CF_V2_PCLXRAW_HEADER_SIZE + CF_V2_PCLXRAW_MAX_MATERIAL ||
      memcmp(data, CF_V2_PCLXRAW_MAGIC, CF_V2_PCLXRAW_MAGIC_SIZE) != 0)
    return 0;
  selector = data + CF_V2_PCLXRAW_MAGIC_SIZE;
  material = data + CF_V2_PCLXRAW_HEADER_SIZE;
  material_size = size - CF_V2_PCLXRAW_HEADER_SIZE;
  cf_v2_pclxraw_decode(selector, &state);
  if (!mkdtemp(directory))
    return 0;

  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_pclxraw_write_ppd(ppd_path, &state) &&
      cf_v2_pclxraw_verify_ppd(ppd_path, &state) &&
      cf_v2_pclxraw_write_raster(raster_path, &state,
                                 material, material_size))
    (void)cf_v2_pclxraw_run_filter(ppd_path, raster_path, &state,
                                  material, material_size);

  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
  return 0;
}

#endif /* !CF_V2_PCLXRAW_ORACLE_ONLY */
