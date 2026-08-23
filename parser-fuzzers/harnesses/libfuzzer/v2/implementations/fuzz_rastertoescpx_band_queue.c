// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef CF_V2_RASTERTOESCPX_SOURCE
#error "CF_V2_RASTERTOESCPX_SOURCE must be a quoted source path"
#endif

#define CF_V2_MAGIC "ESCPWEV1"
#define CF_V2_MAGIC_SIZE 8U
#define CF_V2_SELECTOR_SIZE 8U
#define CF_V2_HEADER_SIZE (CF_V2_MAGIC_SIZE + CF_V2_SELECTOR_SIZE)
#define CF_V2_MAX_BANDS 32U
#define CF_V2_MAX_MATERIAL 1024U

#define main cf_v2_unused_rastertoescpx_main
#include CF_V2_RASTERTOESCPX_SOURCE
#undef main

static unsigned char
cf_v2_material_byte(const uint8_t *material, size_t material_size,
                    size_t index, unsigned int salt)
{
  unsigned char value = material[(index + salt) % material_size];
  return (unsigned char)(value ^ (unsigned char)(index * 29U + salt * 17U));
}

static int
cf_v2_axis_value(unsigned char byte, size_t index, size_t band_count,
                 unsigned int mode, int scale)
{
  static const int boundaries[] = {
    -1024, -256, -1, 0, 1, 2, 127, 255, 256, 1023, 4096
  };

  switch (mode % 6U)
  {
    case 0U : return (int)index * scale;
    case 1U : return (int)(band_count - index) * scale;
    case 2U : return 0;
    case 3U : return (int)(int8_t)byte * scale;
    case 4U :
        return boundaries[byte % (sizeof(boundaries) / sizeof(boundaries[0]))];
    default : return (int)(index % 4U) * scale;
  }
}

static int
cf_v2_key_compare(const cups_weave_t *left, const cups_weave_t *right)
{
  if (left->y != right->y)
    return left->y < right->y ? -1 : 1;
  if (left->x != right->x)
    return left->x < right->x ? -1 : 1;
  if (left->plane != right->plane)
    return left->plane < right->plane ? -1 : 1;
  return 0;
}

static void
cf_v2_stable_sort(size_t *expected, size_t expected_count,
                  const cups_weave_t *bands)
{
  size_t index;

  for (index = 1U; index < expected_count; index ++)
  {
    size_t cursor = index;
    size_t candidate = expected[index];

    while (cursor > 0U &&
           cf_v2_key_compare(&bands[candidate],
                             &bands[expected[cursor - 1U]]) < 0)
    {
      expected[cursor] = expected[cursor - 1U];
      cursor --;
    }
    expected[cursor] = candidate;
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  cups_weave_t bands[CF_V2_MAX_BANDS];
  size_t insertion[CF_V2_MAX_BANDS];
  size_t expected[CF_V2_MAX_BANDS];
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  size_t band_count;
  size_t expected_count = 0U;
  size_t index;
  cups_weave_t *current;
  cups_weave_t *previous = NULL;

  if (size < CF_V2_HEADER_SIZE + 1U ||
      size > CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL ||
      memcmp(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE) != 0)
    return 0;

  selectors = data + CF_V2_MAGIC_SIZE;
  material = data + CF_V2_HEADER_SIZE;
  material_size = size - CF_V2_HEADER_SIZE;
  band_count = 1U + selectors[0] % CF_V2_MAX_BANDS;
  memset(bands, 0, sizeof(bands));
  DotUsedList = NULL;

  for (index = 0U; index < band_count; index ++)
  {
    const unsigned char ybyte = cf_v2_material_byte(
        material, material_size, index * 4U, selectors[7]);
    const unsigned char xbyte = cf_v2_material_byte(
        material, material_size, index * 4U + 1U, selectors[7] + 1U);
    const unsigned char planebyte = cf_v2_material_byte(
        material, material_size, index * 4U + 2U, selectors[7] + 2U);
    const unsigned char countbyte = cf_v2_material_byte(
        material, material_size, index * 4U + 3U, selectors[7] + 3U);

    bands[index].y = cf_v2_axis_value(ybyte, index, band_count,
                                      selectors[1], 1);
    bands[index].x = cf_v2_axis_value(xbyte, index, band_count,
                                      selectors[2], 8);
    switch (selectors[3] % 6U)
    {
      case 0U : bands[index].plane = (int)(planebyte % 7U); break;
      case 1U : bands[index].plane = (int)(index % 7U); break;
      case 2U : bands[index].plane = 6 - (int)(index % 7U); break;
      case 3U : bands[index].plane = 0; break;
      case 4U : bands[index].plane = (planebyte & 1U) ? 6 : 1; break;
      default :
          bands[index].plane = (int)((planebyte + selectors[7]) % 7U);
          break;
    }
    switch ((countbyte + selectors[4] + (unsigned int)index) % 6U)
    {
      case 0U : bands[index].count = -1; break;
      case 1U : bands[index].count = 0; break;
      case 2U : bands[index].count = 1; break;
      case 3U : bands[index].count = 2; break;
      case 4U : bands[index].count = 127; break;
      default : bands[index].count = 128; break;
    }

    if (index > 0U)
    {
      switch (selectors[5] % 5U)
      {
        case 1U : bands[index].y = bands[index - 1U].y; break;
        case 2U :
            bands[index].y = bands[index - 1U].y;
            bands[index].x = bands[index - 1U].x;
            break;
        case 3U :
            bands[index].y = bands[index - 1U].y;
            bands[index].x = bands[index - 1U].x;
            bands[index].plane = bands[index - 1U].plane;
            break;
        case 4U :
            bands[index].y = bands[0].y;
            bands[index].x = bands[0].x;
            bands[index].plane = bands[0].plane;
            break;
        default : break;
      }
    }

  }

  for (index = 0U; index < band_count; index ++)
  {
    const size_t evens = (band_count + 1U) / 2U;
    const size_t odds = band_count / 2U;

    switch (selectors[6] % 4U)
    {
      case 0U : insertion[index] = index; break;
      case 1U : insertion[index] = band_count - index - 1U; break;
      case 2U :
          insertion[index] = index < evens ? 2U * index
                                           : 2U * (index - evens) + 1U;
          break;
      default :
          insertion[index] = index < odds ? 2U * index + 1U
                                          : 2U * (index - odds);
          break;
    }
    if (bands[insertion[index]].count >= 1)
      expected[expected_count ++] = insertion[index];
    AddBand(&bands[insertion[index]]);
  }

  cf_v2_stable_sort(expected, expected_count, bands);
  current = DotUsedList;
  for (index = 0U; index < expected_count; index ++)
  {
    if (current != &bands[expected[index]] || current->prev != previous)
      __builtin_trap();
    if (previous != NULL && previous->next != current)
      __builtin_trap();
    previous = current;
    current = current->next;
  }
  if (current != NULL || (previous != NULL && previous->next != NULL))
    __builtin_trap();

  DotUsedList = NULL;
  return 0;
}
