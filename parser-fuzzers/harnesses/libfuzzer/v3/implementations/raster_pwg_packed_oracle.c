// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define CF_V2_FILTER_FUNCTION cfFilterRasterToPWG
#define CF_V2_TARGET_NAME "fuzz_v3_cupsfilters_raster_to_pwg"
#define CF_V2_INPUT_MIME "application/vnd.cups-raster"
#define CF_V2_OUTPUT_MIME "image/pwg-raster"

#include "raster_pwg_packed_oracle.h"

#include "../../v2/include/direct_route.h"

#include <cups/raster.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
cf_v3_raster_pwg_set_bit(uint8_t *row, unsigned position, unsigned value)
{
  uint8_t mask = (uint8_t)(0x80U >> (position % 8U));

  if (value)
    row[position / 8U] |= mask;
  else
    row[position / 8U] &= (uint8_t)~mask;
}

static uint8_t
cf_v3_raster_pwg_packed_material(const uint8_t *material,
                                 size_t material_size, unsigned pattern,
                                 unsigned row, unsigned offset)
{
  uint8_t value = material_size
                      ? material[((size_t)row * 37U + offset * 17U) %
                                 material_size]
                      : (uint8_t)(row * 29U + offset * 13U + 0x21U);

  switch (pattern % 6U)
  {
    case 0U: return value;
    case 1U: return 0U;
    case 2U: return 0xffU;
    case 3U: return (row + offset) & 1U ? 0xaaU : 0x55U;
    case 4U: return (uint8_t)(1U << ((row + offset) & 7U));
    default: return (uint8_t)(value ^ (uint8_t)(row * 31U + offset));
  }
}

static uint8_t *
cf_v3_raster_pwg_packed_document(const uint8_t selector[12],
                                 const uint8_t *material,
                                 size_t material_size, unsigned *source_width,
                                 unsigned *height, unsigned *left,
                                 unsigned *right, size_t *document_size)
{
  cups_page_header2_t header;
  size_t source_bytes;
  size_t total;
  uint8_t *document;
  size_t offset;

  *source_width = 8U * (1U + selector[1] % 8U);
  *height = 1U + selector[2] % 8U;
  *left = selector[3] % 24U;
  *right = selector[4] % 17U;
  source_bytes = (*source_width + 7U) / 8U;
  total = 4U + sizeof(header) + (size_t)*height * source_bytes;
  document = (uint8_t *)malloc(total);
  if (!document)
    return NULL;
  memset(&header, 0, sizeof(header));
  memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
  memcpy(header.MediaType, "stationery", sizeof("stationery"));
  memcpy(header.cupsPageSizeName, "Packed", sizeof("Packed"));
  header.HWResolution[0] = 72U;
  header.HWResolution[1] = 72U;
  header.PageSize[0] = *source_width + *left + *right;
  header.PageSize[1] = *height;
  header.ImagingBoundingBox[0] = *left;
  header.ImagingBoundingBox[2] = *left + *source_width;
  header.ImagingBoundingBox[3] = *height;
  header.cupsPageSize[0] = (float)header.PageSize[0];
  header.cupsPageSize[1] = (float)header.PageSize[1];
  header.cupsImagingBBox[0] = (float)*left;
  header.cupsImagingBBox[2] = (float)(*left + *source_width);
  header.cupsImagingBBox[3] = (float)*height;
  header.cupsWidth = *source_width;
  header.cupsHeight = *height;
  header.cupsBitsPerColor = 1U;
  header.cupsBitsPerPixel = 1U;
  header.cupsBytesPerLine = (unsigned)source_bytes;
  header.cupsColorOrder = CUPS_ORDER_CHUNKED;
  header.cupsColorSpace = CUPS_CSPACE_SW;
  header.cupsCompression = 0U;
  header.cupsRowCount = 1U;
  header.cupsRowFeed = 1U;
  header.cupsRowStep = 1U;
  header.cupsNumColors = 1U;
  header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] = 1U;
  header.NumCopies = 1U;
  memcpy(document, "3SaR", 4U);
  memcpy(document + 4U, &header, sizeof(header));
  offset = 4U + sizeof(header);
  for (unsigned row = 0U; row < *height; row ++)
    for (size_t byte = 0U; byte < source_bytes; byte ++)
      document[offset ++] = cf_v3_raster_pwg_packed_material(
          material, material_size, selector[8], row, (unsigned)byte);
  *document_size = total;
  return document;
}

static int
cf_v3_raster_pwg_check_packed(const cf_v2_run_result_t *result,
                              const uint8_t selector[12],
                              const uint8_t *material, size_t material_size,
                              unsigned source_width, unsigned height,
                              unsigned left, unsigned right,
                              int *packed_mismatch)
{
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  FILE *file = NULL;
  uint8_t *actual = NULL;
  uint8_t *expected = NULL;
  size_t output_bytes = (source_width + left + right + 7U) / 8U;
  int fd = -1;
  int valid = 0;

  *packed_mismatch = 0;
  if (!result->captured || result->status != 0 || !result->output_size)
    goto cleanup;
  file = tmpfile();
  actual = (uint8_t *)malloc(output_bytes);
  expected = (uint8_t *)malloc(output_bytes);
  if (!file || !actual || !expected ||
      fwrite(result->output, 1U, result->output_size, file) !=
          result->output_size ||
      fflush(file) != 0 || fseek(file, 0, SEEK_SET) != 0 ||
      (fd = dup(fileno(file))) < 0 ||
      !(raster = cupsRasterOpen(fd, CUPS_RASTER_READ)) ||
      !cupsRasterReadHeader2(raster, &header))
    goto cleanup;
  if (header.cupsWidth != source_width + left + right ||
      header.cupsHeight != height || header.cupsBitsPerPixel != 1U ||
      header.cupsBytesPerLine != output_bytes ||
      header.cupsInteger[CUPS_RASTER_PWG_ImageBoxLeft] != left ||
      header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] !=
          left + source_width)
    goto cleanup;
  for (unsigned row = 0U; row < height; row ++)
  {
    if (cupsRasterReadPixels(raster, actual, output_bytes) != output_bytes)
      goto cleanup;
    memset(expected, 0xff, output_bytes);
    for (unsigned source_x = 0U; source_x < source_width; source_x ++)
    {
      uint8_t source = cf_v3_raster_pwg_packed_material(
          material, material_size, selector[8], row, source_x / 8U);
      cf_v3_raster_pwg_set_bit(
          expected, left + source_x,
          (source >> (7U - source_x % 8U)) & 1U);
    }
    if (memcmp(actual, expected, output_bytes) != 0)
      *packed_mismatch = 1;
  }
  valid = 1;

cleanup:
  if (raster)
    cupsRasterClose(raster);
  if (fd >= 0)
    close(fd);
  if (file)
    fclose(file);
  free(actual);
  free(expected);
  return valid;
}

int
cf_v3_raster_pwg_packed_oracle(const uint8_t selector[12],
                                const uint8_t *material,
                                size_t material_size, int faithful)
{
  cf_v2_control_t control;
  cf_v2_run_result_t result = {0};
  uint8_t *document;
  size_t document_size = 0U;
  unsigned source_width;
  unsigned height;
  unsigned left;
  unsigned right;
  int packed_mismatch = 0;
  int executed;
  int valid;
  int fail;

  document = cf_v3_raster_pwg_packed_document(
      selector, material, material_size, &source_width, &height, &left,
      &right, &document_size);
  if (!document)
    return 0;
  memset(&control, 0, sizeof(control));
  executed = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &result);
  valid = executed && cf_v3_raster_pwg_check_packed(
                          &result, selector, material, material_size,
                          source_width, height, left, right, &packed_mismatch);
  fail = !valid || (packed_mismatch && (faithful || left % 8U == 0U));
  if (getenv("CF_V3_TRACE_RASTER_PWG"))
    fprintf(stderr,
            "raster-pwg-packed: left=%u width=%u mismatch=%d faithful=%d\n",
            left, source_width, packed_mismatch, faithful);
  cf_v2_free_run_result(&result);
  free(document);
  if (fail)
    __builtin_trap();
  return 0;
}
