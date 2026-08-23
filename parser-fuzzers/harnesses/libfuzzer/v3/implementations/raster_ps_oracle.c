// SPDX-License-Identifier: Apache-2.0
#include "raster_ps_oracle.h"

#include "../../v2/include/direct_route.h"

#include <cups/raster.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define CF_V3_RASTER_PS_MAX_PAGES 3U
#define CF_V3_RASTER_PS_DECODE_LIMIT (64U * 1024U)

typedef struct cf_v3_raster_ps_format_s
{
  cups_cspace_t color_space;
  unsigned colors;
  unsigned bits_per_color;
} cf_v3_raster_ps_format_t;

typedef struct cf_v3_raster_ps_page_s
{
  unsigned width;
  unsigned height;
  unsigned bytes_per_line;
  cf_v3_raster_ps_format_t format;
  uint8_t *raster;
  size_t raster_size;
  uint8_t *expected;
  size_t expected_size;
  size_t available_size;
} cf_v3_raster_ps_page_t;

static void
cf_v3_raster_ps_fail(void)
{
  __builtin_trap();
}

static uint8_t
cf_v3_raster_ps_material(const uint8_t *material, size_t material_size,
                         unsigned page, size_t offset)
{
  if (material_size)
    return material[(offset + (size_t)page * 131U) % material_size];
  return (uint8_t)(17U + page * 53U + offset * 97U);
}

static int
cf_v3_raster_ps_rgb_one_bit(cups_cspace_t color_space)
{
  return color_space == CUPS_CSPACE_RGB ||
         color_space == CUPS_CSPACE_SRGB ||
         color_space == CUPS_CSPACE_ADOBERGB;
}

static int
cf_v3_raster_ps_prepare_page(cf_v3_raster_ps_page_t *page,
                             const uint8_t *material, size_t material_size,
                             unsigned page_number)
{
  size_t output_offset = 0U;

  page->bytes_per_line =
      (page->width * page->format.colors * page->format.bits_per_color + 7U) /
      8U;
  if (!page->bytes_per_line || !page->height ||
      page->bytes_per_line > SIZE_MAX / page->height)
    return 0;
  page->raster_size = (size_t)page->bytes_per_line * page->height;
  page->expected_size = page->raster_size;
  if (page->format.bits_per_color == 1U &&
      cf_v3_raster_ps_rgb_one_bit(page->format.color_space))
  {
    if (page->expected_size > SIZE_MAX / 6U)
      return 0;
    page->expected_size *= 6U;
  }
  page->raster = (uint8_t *)malloc(page->raster_size);
  page->expected = (uint8_t *)malloc(page->expected_size);
  if (!page->raster || !page->expected)
    return 0;
  for (size_t index = 0; index < page->raster_size; index++)
    page->raster[index] = cf_v3_raster_ps_material(
        material, material_size, page_number, index);

  if (page->format.bits_per_color == 1U &&
      cf_v3_raster_ps_rgb_one_bit(page->format.color_space))
  {
    static const uint8_t masks[] = {0x40U, 0x20U, 0x10U,
                                    0x04U, 0x02U, 0x01U};

    for (size_t index = 0; index < page->raster_size; index++)
      for (size_t bit = 0; bit < sizeof(masks); bit++)
        page->expected[output_offset++] =
            page->raster[index] & masks[bit] ? 0xffU : 0x00U;
  }
  else
    memcpy(page->expected, page->raster, page->raster_size);
  page->available_size = page->raster_size;
  return 1;
}

static void
cf_v3_raster_ps_release_pages(cf_v3_raster_ps_page_t *pages,
                              unsigned page_count)
{
  for (unsigned page = 0; page < page_count; page++)
  {
    free(pages[page].raster);
    free(pages[page].expected);
    memset(&pages[page], 0, sizeof(pages[page]));
  }
}

static uint8_t *
cf_v3_raster_ps_document(cf_v3_raster_ps_page_t *pages,
                         unsigned page_count, size_t *document_size)
{
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;

  for (unsigned page = 0; page < page_count; page++)
  {
    if (sizeof(cups_page_header2_t) > SIZE_MAX - total ||
        pages[page].available_size >
            SIZE_MAX - total - sizeof(cups_page_header2_t))
      return NULL;
    total += sizeof(cups_page_header2_t) + pages[page].available_size;
  }
  document = (uint8_t *)malloc(total);
  if (!document)
    return NULL;
  memcpy(document, "3SaR", 4U);
  for (unsigned page = 0; page < page_count; page++)
  {
    cups_page_header2_t header;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = pages[page].width;
    header.PageSize[1] = pages[page].height;
    header.ImagingBoundingBox[2] = pages[page].width;
    header.ImagingBoundingBox[3] = pages[page].height;
    header.cupsPageSize[0] = (float)pages[page].width;
    header.cupsPageSize[1] = (float)pages[page].height;
    header.cupsImagingBBox[2] = (float)pages[page].width;
    header.cupsImagingBBox[3] = (float)pages[page].height;
    header.cupsWidth = pages[page].width;
    header.cupsHeight = pages[page].height;
    header.cupsBitsPerColor = pages[page].format.bits_per_color;
    header.cupsBitsPerPixel = pages[page].format.colors *
                              pages[page].format.bits_per_color;
    header.cupsBytesPerLine = pages[page].bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = pages[page].format.color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = pages[page].format.colors;
    header.NumCopies = 1U;
    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);
    if (pages[page].available_size)
      memcpy(document + offset, pages[page].raster,
             pages[page].available_size);
    offset += pages[page].available_size;
  }
  *document_size = total;
  return document;
}

static const uint8_t *
cf_v3_raster_ps_find(const uint8_t *data, size_t size,
                     const char *needle, size_t needle_size)
{
  if (needle_size > size)
    return NULL;
  for (size_t index = 0; index <= size - needle_size; index++)
    if (!memcmp(data + index, needle, needle_size))
      return data + index;
  return NULL;
}

static int
cf_v3_raster_ps_inflate(const uint8_t *data, size_t size,
                        uint8_t *decoded, size_t decoded_capacity,
                        size_t *consumed, size_t *decoded_size)
{
  z_stream stream;
  int status;

  if (size > UINT_MAX || decoded_capacity > UINT_MAX)
    return 0;
  memset(&stream, 0, sizeof(stream));
  stream.next_in = (Bytef *)data;
  stream.avail_in = (uInt)size;
  stream.next_out = decoded;
  stream.avail_out = (uInt)decoded_capacity;
  if (inflateInit(&stream) != Z_OK)
    return 0;
  do
    status = inflate(&stream, Z_NO_FLUSH);
  while (status == Z_OK && stream.avail_out);
  if (status != Z_STREAM_END)
  {
    inflateEnd(&stream);
    return 0;
  }
  *consumed = stream.total_in;
  *decoded_size = stream.total_out;
  inflateEnd(&stream);
  return 1;
}

static int
cf_v3_raster_ps_validate_output(const cf_v2_run_result_t *result,
                                cf_v3_raster_ps_page_t *pages,
                                unsigned page_count, int allow_truncated)
{
  static const char image_marker[] = ">> image\n";
  const uint8_t *cursor;
  size_t remaining;
  uint8_t *decoded;

  if (!result->captured || result->status != 0 ||
      !result->output || result->output_size < 16U ||
      memcmp(result->output, "%!PS-Adobe-3.0\n", 15U))
    return 0;
  decoded = (uint8_t *)malloc(CF_V3_RASTER_PS_DECODE_LIMIT);
  if (!decoded)
    return 0;
  cursor = result->output;
  remaining = result->output_size;
  for (unsigned page = 0; page < page_count; page++)
  {
    const uint8_t *marker = cf_v3_raster_ps_find(
        cursor, remaining, image_marker, sizeof(image_marker) - 1U);
    size_t prefix;
    size_t consumed;
    size_t decoded_size;

    if (!marker)
    {
      free(decoded);
      return allow_truncated && page > 0U;
    }
    marker += sizeof(image_marker) - 1U;
    prefix = (size_t)(marker - cursor);
    if (prefix > remaining ||
        !cf_v3_raster_ps_inflate(marker, remaining - prefix, decoded,
                                 CF_V3_RASTER_PS_DECODE_LIMIT,
                                 &consumed, &decoded_size))
    {
      free(decoded);
      return 0;
    }
    if (allow_truncated && page == 1U)
    {
      if (decoded_size > pages[page].available_size)
      {
        free(decoded);
        cf_v3_raster_ps_fail();
      }
      if (decoded_size &&
          memcmp(decoded, pages[page].expected, decoded_size))
      {
        free(decoded);
        cf_v3_raster_ps_fail();
      }
    }
    else if (decoded_size != pages[page].expected_size ||
             memcmp(decoded, pages[page].expected, decoded_size))
    {
      free(decoded);
      cf_v3_raster_ps_fail();
    }
    if (prefix + consumed > remaining)
    {
      free(decoded);
      return 0;
    }
    cursor += prefix + consumed;
    remaining -= prefix + consumed;
  }
  free(decoded);
  if (cf_v3_raster_ps_find(cursor, remaining, image_marker,
                           sizeof(image_marker) - 1U))
    cf_v3_raster_ps_fail();
  return 1;
}

static int
cf_v3_raster_ps_execute(cf_v3_raster_ps_page_t *pages,
                        unsigned page_count, int allow_truncated,
                        const uint8_t *header)
{
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  uint8_t *document;
  size_t document_size;
  int executed;

  document = cf_v3_raster_ps_document(pages, page_count, &document_size);
  if (!document)
    return 0;
  memcpy(&control, header + 9U, sizeof(control));
  executed = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &result);
  if (executed)
    (void)cf_v3_raster_ps_validate_output(&result, pages, page_count,
                                          allow_truncated);
  cf_v2_free_run_result(&result);
  free(document);
  return 0;
}

int
cf_v3_raster_ps_truncation_oracle(const uint8_t *header,
                                  const uint8_t *material,
                                  size_t material_size, int faithful)
{
  static const uint8_t marker[] =
      "LEAK-MARKER-0123456789abcdef-RASTER-TO-POSTSCRIPT-ROW";
  cf_v3_raster_ps_page_t pages[2];
  const size_t available = faithful ? (size_t)(header[26] % 64U) : 64U;
  int result;

  memset(pages, 0, sizeof(pages));
  for (unsigned page = 0; page < 2U; page++)
  {
    pages[page].width = 64U;
    pages[page].height = 1U;
    pages[page].format.color_space = CUPS_CSPACE_K;
    pages[page].format.colors = 1U;
    pages[page].format.bits_per_color = 8U;
    if (!cf_v3_raster_ps_prepare_page(&pages[page], material,
                                      material_size, page))
    {
      cf_v3_raster_ps_release_pages(pages, 2U);
      return 0;
    }
  }
  for (size_t index = 0; index < pages[0].raster_size; index++)
    pages[0].raster[index] = marker[index % (sizeof(marker) - 1U)];
  memcpy(pages[0].expected, pages[0].raster, pages[0].raster_size);
  for (size_t index = 0; index < pages[1].raster_size; index++)
    pages[1].raster[index] = (uint8_t)(0xa5U ^ (uint8_t)(index * 37U));
  memcpy(pages[1].expected, pages[1].raster, pages[1].raster_size);
  pages[1].available_size = available;
  result = cf_v3_raster_ps_execute(pages, 2U, faithful, header);
  cf_v3_raster_ps_release_pages(pages, 2U);
  return result;
}

int
cf_v3_raster_ps_output_oracle(const uint8_t *header,
                              const uint8_t *material,
                              size_t material_size)
{
  static const cf_v3_raster_ps_format_t formats[] = {
    {CUPS_CSPACE_K, 1U, 1U},
    {CUPS_CSPACE_K, 1U, 8U},
    {CUPS_CSPACE_K, 1U, 16U},
    {CUPS_CSPACE_RGB, 3U, 1U},
    {CUPS_CSPACE_RGB, 3U, 8U},
    {CUPS_CSPACE_RGB, 3U, 16U},
    {CUPS_CSPACE_CMYK, 4U, 8U},
    {CUPS_CSPACE_SW, 1U, 8U},
  };
  static const unsigned widths[] = {1U, 2U, 7U, 8U, 15U, 31U, 64U};
  cf_v3_raster_ps_page_t pages[CF_V3_RASTER_PS_MAX_PAGES];
  unsigned page_count = 1U + header[27] % CF_V3_RASTER_PS_MAX_PAGES;
  int result;

  memset(pages, 0, sizeof(pages));
  for (unsigned page = 0; page < page_count; page++)
  {
    pages[page].width = widths[(header[1] + page * 3U) %
                              (sizeof(widths) / sizeof(widths[0]))];
    pages[page].height = 1U + (header[2] + page) % 4U;
    pages[page].format = formats[(header[3] + page *
                                 (1U + header[4] % 5U)) %
                                (sizeof(formats) / sizeof(formats[0]))];
    if (!cf_v3_raster_ps_prepare_page(&pages[page], material,
                                      material_size, page))
    {
      cf_v3_raster_ps_release_pages(pages, page_count);
      return 0;
    }
  }
  result = cf_v3_raster_ps_execute(pages, page_count, 0, header);
  cf_v3_raster_ps_release_pages(pages, page_count);
  return result;
}
