// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "pwg_raster_bridge.h"
#include "pwg_raster_lcms_adapter.h"
#include "pwg_raster_route.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"
#include "../../v2/include/profiles.h"

#include <cups/raster.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V3_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

extern int cf_v3_pwg_raster_direct_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_job_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_scale_up_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_scale_down_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_relation_h_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_relation_v_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_relation_p_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_arith_h_boundary_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_arith_h_deep_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_arith_v_boundary_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_arith_v_deep_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_arith_p_boundary_legacy(const uint8_t *, size_t);
extern int cf_v3_pwg_raster_arith_p_deep_legacy(const uint8_t *, size_t);

typedef int (*cf_v3_pwg_raster_runner_t)(const uint8_t *, size_t);

static const cf_v3_pwg_raster_runner_t cf_v3_pwg_raster_arithmetic[] = {
  cf_v3_pwg_raster_arith_h_boundary_legacy,
  cf_v3_pwg_raster_arith_h_deep_legacy,
  cf_v3_pwg_raster_arith_v_boundary_legacy,
  cf_v3_pwg_raster_arith_v_deep_legacy,
  cf_v3_pwg_raster_arith_p_boundary_legacy,
  cf_v3_pwg_raster_arith_p_deep_legacy
};

static int
cf_v3_pwg_raster_call(cf_v3_pwg_raster_runner_t runner,
                      const uint8_t *data, size_t size)
{
  int result;

  cf_v3_pwg_raster_lcms_begin();
  result = runner(data, size);
  cf_v3_pwg_raster_lcms_end();
  if (getenv("CF_V3_TRACE_PWG_RASTER") &&
      cf_v3_pwg_raster_lcms_overflowed())
    fprintf(stderr, "pwg-raster-route: lcms tracker overflow\n");
  return result;
}

static uint8_t
cf_v3_pwg_raster_material(const cf_v2_arithmetic_layout_t *layout,
                          size_t offset)
{
  uint8_t value = layout->opaque.size
                      ? layout->opaque.data[(offset + layout->material_phase) %
                                            layout->opaque.size]
                      : (uint8_t)(offset * 131U + layout->material_phase * 17U);

  switch (layout->pattern % 6U)
  {
    case 0U: return value;
    case 1U: return 0U;
    case 2U: return 0xffU;
    case 3U: return offset & 1U ? 0xaaU : 0x55U;
    case 4U: return (uint8_t)offset;
    default: return (uint8_t)(value ^ (uint8_t)(offset * 29U));
  }
}

static void
cf_v3_pwg_raster_source_profile(
    cf_v2_arithmetic_source_format_t format, cups_cspace_t *color_space,
    unsigned *bits_per_color, unsigned *bits_per_pixel,
    unsigned *num_colors)
{
  if (format == CF_V2_ARITHMETIC_SOURCE_RGB8)
  {
    *color_space = CUPS_CSPACE_SRGB;
    *bits_per_color = 8U;
    *bits_per_pixel = 24U;
    *num_colors = 3U;
  }
  else if (format == CF_V2_ARITHMETIC_SOURCE_BLACK1)
  {
    *color_space = CUPS_CSPACE_K;
    *bits_per_color = 1U;
    *bits_per_pixel = 1U;
    *num_colors = 1U;
  }
  else
  {
    *color_space = CUPS_CSPACE_W;
    *bits_per_color = 8U;
    *bits_per_pixel = 8U;
    *num_colors = 1U;
  }
}

static uint8_t *
cf_v3_pwg_raster_document(const cf_v2_arithmetic_layout_t *layout,
                          size_t *document_size)
{
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  FILE *file = NULL;
  uint8_t *row = NULL;
  uint8_t *document = NULL;
  cups_cspace_t color_space;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
  unsigned num_colors;
  unsigned width = layout->source_width;
  unsigned height = layout->source_height;
  unsigned pages = 1U + (layout->input_pages.parameter & 1U);
  size_t bytes_per_line;
  long length;
  int write_fd = -1;

  cf_v3_pwg_raster_source_profile(layout->source_format, &color_space,
                                  &bits_per_color, &bits_per_pixel,
                                  &num_colors);
  bytes_per_line = ((size_t)width * bits_per_pixel + 7U) / 8U;
  if (!bytes_per_line || bytes_per_line > 4096U || height > 256U)
    return NULL;
  file = tmpfile();
  row = (uint8_t *)malloc(bytes_per_line);
  if (!file || !row || (write_fd = dup(fileno(file))) < 0 ||
      !(raster = cupsRasterOpen(write_fd, CUPS_RASTER_WRITE_PWG)))
    goto cleanup;
  for (unsigned page = 0U; page < pages; page ++)
  {
    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "Plain", sizeof("Plain"));
    memcpy(header.cupsPageSizeName, "Tiny", sizeof("Tiny"));
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = width;
    header.PageSize[1] = height;
    header.ImagingBoundingBox[2] = width;
    header.ImagingBoundingBox[3] = height;
    header.cupsPageSize[0] = (float)width;
    header.cupsPageSize[1] = (float)height;
    header.cupsImagingBBox[2] = (float)width;
    header.cupsImagingBBox[3] = (float)height;
    header.cupsWidth = width;
    header.cupsHeight = height;
    header.cupsBitsPerColor = bits_per_color;
    header.cupsBitsPerPixel = bits_per_pixel;
    header.cupsBytesPerLine = (unsigned)bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = num_colors;
    header.NumCopies = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_CrossFeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_FeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] = width;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] = height;
    if (!cupsRasterWriteHeader2(raster, &header))
      goto cleanup;
    for (unsigned y = 0U; y < height; y ++)
    {
      for (size_t x = 0U; x < bytes_per_line; x ++)
        row[x] = cf_v3_pwg_raster_material(
            layout, ((size_t)page * height + y) * bytes_per_line + x);
      if (cupsRasterWritePixels(raster, row, bytes_per_line) != bytes_per_line)
        goto cleanup;
    }
  }
  cupsRasterClose(raster);
  raster = NULL;
  close(write_fd);
  write_fd = -1;
  if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) <= 0 ||
      (unsigned long)length > 2U * 1024U * 1024U ||
      fseek(file, 0, SEEK_SET) != 0 ||
      !(document = (uint8_t *)malloc((size_t)length)) ||
      fread(document, 1U, (size_t)length, file) != (size_t)length)
  {
    free(document);
    document = NULL;
    goto cleanup;
  }
  *document_size = (size_t)length;

cleanup:
  if (raster)
    cupsRasterClose(raster);
  if (write_fd >= 0)
    close(write_fd);
  free(row);
  if (file)
    fclose(file);
  return document;
}

static void
cf_v3_pwg_raster_control(const cf_v2_arithmetic_layout_t *layout,
                         cf_v2_control_t *control)
{
  memset(control, 0, sizeof(*control));
  control->ppd_profile = layout->option_mode;
  control->page_size = layout->geometry_phase;
  control->color_model = (uint8_t)layout->output_color_space;
  control->resolution = (uint8_t)layout->output_resolution_x.explicit_value;
  control->sides = layout->actions.encoded[0];
  control->orientation = layout->axis_relation;
  control->scaling = (uint8_t)layout->natural_scaling.explicit_value;
  control->copies = layout->copies.parameter;
  control->number_up = layout->x_pages.parameter;
  control->position = layout->y_pages.parameter;
  control->quality = layout->pattern;
  control->output_order = layout->output_color_order;
  control->media_type = layout->material_phase;
  control->mirror = layout->actions.encoded[1];
  control->route_mode = layout->spare;
  control->reserved = layout->opaque_mode;
}

static uint8_t *
cf_v3_pwg_raster_direct_input(const cf_v2_arithmetic_layout_t *layout,
                              const uint8_t *document, size_t document_size,
                              size_t *input_size)
{
  cf_v2_control_t control;
  uint8_t *input;

  if (document_size > SIZE_MAX - CF_V2_CONTROL_SIZE)
    return NULL;
  input = (uint8_t *)malloc(document_size + CF_V2_CONTROL_SIZE);
  if (!input)
    return NULL;
  cf_v3_pwg_raster_control(layout, &control);
  memcpy(input, document, document_size);
  memcpy(input + document_size, &control, CF_V2_CONTROL_SIZE);
  *input_size = document_size + CF_V2_CONTROL_SIZE;
  return input;
}

static uint8_t *
cf_v3_pwg_raster_job_input(const cf_v2_arithmetic_layout_t *layout,
                           const uint8_t *document, size_t document_size,
                           size_t *input_size)
{
  static const char title[] = "PWG raster V3";
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  FILE *stream;
  uint8_t *input = NULL;
  size_t ppd_size = 0U;
  size_t options_size;
  size_t title_size = sizeof(title) - 1U;
  size_t total;
  size_t offset;
  int ppd_status;
  int close_status;

  cf_v3_pwg_raster_control(layout, &control);
  stream = open_memstream(&ppd, &ppd_size);
  if (!stream)
    return NULL;
  ppd_status = cf_v2_write_ppd(stream, &control, "pwgtoraster");
  close_status = fclose(stream);
  if (ppd_status != 0 || close_status != 0 ||
      cf_v2_build_options(options, sizeof(options), &control) != 0)
  {
    free(ppd);
    return NULL;
  }
  options_size = strlen(options);
  total = CF_V2_JOB_FIXED_SIZE;
  if (ppd_size > SIZE_MAX - total ||
      options_size > SIZE_MAX - total - ppd_size ||
      title_size > SIZE_MAX - total - ppd_size - options_size ||
      document_size > SIZE_MAX - total - ppd_size - options_size - title_size)
    goto cleanup;
  total += ppd_size + options_size + title_size + document_size;
  input = (uint8_t *)malloc(total);
  if (!input)
    goto cleanup;
  cf_v2_job_store_u32le(input, (uint32_t)ppd_size);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)options_size);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_size);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)document_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, &control, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, ppd, ppd_size);
  offset += ppd_size;
  memcpy(input + offset, options, options_size);
  offset += options_size;
  memcpy(input + offset, title, title_size);
  offset += title_size;
  memcpy(input + offset, document, document_size);
  *input_size = total;

cleanup:
  free(ppd);
  return input;
}

static int
cf_v3_pwg_raster_run_public(unsigned route,
                            const cf_v2_arithmetic_layout_t *layout)
{
  const uint8_t *document;
  uint8_t *generated = NULL;
  uint8_t *input = NULL;
  size_t document_size;
  size_t input_size = 0U;

  if (route == CF_V3_PWG_RASTER_ROUTE_DIRECT &&
      layout->option_mode == 3U)
  {
    document = layout->opaque.data;
    document_size = layout->opaque.size;
  }
  else
  {
    generated = cf_v3_pwg_raster_document(layout, &document_size);
    document = generated;
  }
  if (!document || !document_size)
    goto cleanup;
  if (route == CF_V3_PWG_RASTER_ROUTE_DIRECT)
    input = cf_v3_pwg_raster_direct_input(layout, document, document_size,
                                          &input_size);
  else
    input = cf_v3_pwg_raster_job_input(layout, document, document_size,
                                       &input_size);
  if (input)
  {
    if (route == CF_V3_PWG_RASTER_ROUTE_DIRECT)
      (void)cf_v3_pwg_raster_call(cf_v3_pwg_raster_direct_legacy,
                                  input, input_size);
    else
      (void)cf_v3_pwg_raster_call(cf_v3_pwg_raster_job_legacy,
                                  input, input_size);
  }

cleanup:
  free(input);
  free(generated);
  return 0;
}

static int
cf_v3_pwg_raster_run_compact(unsigned route, const uint8_t *header,
                             const uint8_t *material, size_t material_size,
                             int faithful)
{
  uint8_t input[8U + 8U + 4096U];
  uint8_t *selector;
  const char *magic;
  size_t magic_size;
  cf_v3_pwg_raster_runner_t runner;

  if (route == CF_V3_PWG_RASTER_ROUTE_SCALE_UP ||
      route == CF_V3_PWG_RASTER_ROUTE_SCALE_DOWN)
  {
    magic = "PWGSCL1";
    magic_size = 7U;
    runner = route == CF_V3_PWG_RASTER_ROUTE_SCALE_UP
                 ? cf_v3_pwg_raster_scale_up_legacy
                 : cf_v3_pwg_raster_scale_down_legacy;
  }
  else
  {
    magic = "PWGRREL1";
    magic_size = 8U;
    if (route == CF_V3_PWG_RASTER_ROUTE_HORIZONTAL_RELATION)
      runner = cf_v3_pwg_raster_relation_h_legacy;
    else if (route == CF_V3_PWG_RASTER_ROUTE_VERTICAL_RELATION)
      runner = cf_v3_pwg_raster_relation_v_legacy;
    else
      runner = cf_v3_pwg_raster_relation_p_legacy;
  }
  memcpy(input, magic, magic_size);
  selector = input + magic_size;
  selector[0] = header[0] ^ header[41];
  selector[1] = header[2] ^ header[43];
  selector[2] = header[27] ^ header[45];
  selector[3] = header[30] ^ header[47];
  selector[4] = (uint8_t)((header[4] % 3U) |
                          ((header[5] % 4U) << 4U));
  selector[5] = (uint8_t)((header[7] % 3U) |
                          ((header[60] & 1U) << 4U));
  selector[6] = header[72] ^ header[76];
  selector[7] = header[77] ^ header[78];
  if (route >= CF_V3_PWG_RASTER_ROUTE_HORIZONTAL_RELATION &&
      route <= CF_V3_PWG_RASTER_ROUTE_PLANAR_RELATION)
    selector[4] = faithful ? 2U : (uint8_t)(header[45 +
        2U * (route - CF_V3_PWG_RASTER_ROUTE_HORIZONTAL_RELATION)] & 1U);
  memcpy(selector + 8U, material, material_size);
  return cf_v3_pwg_raster_call(runner, input,
                               magic_size + 8U + material_size);
}

static void
cf_v3_pwg_raster_safe_arithmetic(uint8_t *input, unsigned route)
{
  uint8_t *header = cf_v3_pwg_raster_header(input);
  unsigned product_offset;

  /* LARGE line_bytes can encode a 512-KiB one-bit row, turning a small
   * product into more than four million per-pixel iterations. The 64-KiB
   * boundary neighborhood preserves wide-row arithmetic without consuming
   * nearly the entire OSS-Fuzz timeout. Faithful regression inputs keep the
   * original class. */
  if (header[42] % CF_V2_CARDINALITY_CLASS_COUNT ==
      CF_V2_CARDINALITY_LARGE)
    header[42] = CF_V2_CARDINALITY_BOUNDARY_NEIGHBOR;

  if (route <= CF_V3_PWG_RASTER_ROUTE_HORIZONTAL_DEEP)
  {
    product_offset = 44U;
    header[14] &= (uint8_t)~1U;
    header[26] &= (uint8_t)~1U;
  }
  else if (route <= CF_V3_PWG_RASTER_ROUTE_VERTICAL_DEEP)
  {
    product_offset = 46U;
    header[17] &= (uint8_t)~1U;
    header[29] &= (uint8_t)~1U;
  }
  else
    product_offset = 48U;

  /* Any near-2^32 product can round up after division by line_bytes and
   * reproduce the already known wrapped allocation. Keep the generic
   * low-cardinality state space in deployment; faithful runs retain the
   * complete relation for regression and local root exploration. */
  if (header[product_offset] % CF_V2_CARDINALITY_CLASS_COUNT >=
      CF_V2_CARDINALITY_BOUNDARY_NEIGHBOR)
    header[product_offset] = CF_V2_CARDINALITY_SMALL;
}

static int
cf_v3_pwg_raster_run_arithmetic(unsigned route, const uint8_t *data,
                                size_t size, int faithful)
{
  uint8_t *input = (uint8_t *)malloc(size);
  unsigned index = route - CF_V3_PWG_RASTER_ROUTE_HORIZONTAL_BOUNDARY;

  if (!input || index >= CF_V3_ARRAY_SIZE(cf_v3_pwg_raster_arithmetic))
  {
    free(input);
    return 0;
  }
  memcpy(input, data, size);
  if (!faithful)
    cf_v3_pwg_raster_safe_arithmetic(input, route);
  (void)cf_v3_pwg_raster_call(cf_v3_pwg_raster_arithmetic[index],
                              input, size);
  free(input);
  return 0;
}

int
cf_v3_pwg_raster_bridge(const uint8_t *data, size_t size)
{
  cf_v2_arithmetic_layout_t layout;
  const uint8_t *header;
  const uint8_t *material;
  size_t material_size;
  unsigned route;
  int faithful;

  if (!cf_v3_pwg_raster_input(data, size) ||
      !cf_v2_arithmetic_layout_parse(data, size, &layout))
    return 0;
  header = cf_v3_pwg_raster_const_header(data);
  material = data + CF_V3_PWG_RASTER_FIXED_SIZE;
  material_size = size - CF_V3_PWG_RASTER_FIXED_SIZE;
  route = cf_v3_pwg_raster_route(header);
  faithful = cf_v3_pwg_raster_faithful(header);
  if (getenv("CF_V3_TRACE_PWG_RASTER"))
    fprintf(stderr, "pwg-raster-route: route=%u faithful=%d format=%u\n",
            route, faithful, (unsigned)layout.source_format);

  if (route <= CF_V3_PWG_RASTER_ROUTE_JOB)
    return cf_v3_pwg_raster_run_public(route, &layout);
  if (route <= CF_V3_PWG_RASTER_ROUTE_PLANAR_RELATION)
    return cf_v3_pwg_raster_run_compact(route, header, material,
                                        material_size, faithful);
  return cf_v3_pwg_raster_run_arithmetic(route, data, size, faithful);
}
