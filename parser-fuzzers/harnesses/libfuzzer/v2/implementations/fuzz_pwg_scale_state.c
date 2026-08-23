// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "../include/runtime.h"

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/filter.h>
#include <ppd/ppd-filter.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CF_V2_PWG_RELATION_PROGRAM
#define CF_V2_PWG_SCALE_MAGIC "PWGRREL1"
#else
#define CF_V2_PWG_SCALE_MAGIC "PWGSCL1"
#endif
#define CF_V2_PWG_SCALE_SELECTORS 8U
#define CF_V2_PWG_SCALE_MAX_MATERIAL 4096U

#ifdef CF_V2_PWG_RELATION_PROGRAM
#ifndef CF_V2_PWG_RELATION_LANE
#error "CF_V2_PWG_RELATION_LANE must select one relation boundary"
#endif
#if CF_V2_PWG_RELATION_LANE < 1 || CF_V2_PWG_RELATION_LANE > 3
#error "unsupported CF_V2_PWG_RELATION_LANE"
#endif
#else
#if !defined(CF_V2_PWG_SCALE_UP) && !defined(CF_V2_PWG_SCALE_DOWN)
#error "Select one PWG scale direction"
#endif

#if defined(CF_V2_PWG_SCALE_UP) && defined(CF_V2_PWG_SCALE_DOWN)
#error "Select only one PWG scale direction"
#endif
#endif

typedef struct cf_v2_pwg_scale_format_s {
  cups_cspace_t color_space;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
  unsigned num_colors;
} cf_v2_pwg_scale_format_t;

typedef struct cf_v2_pwg_scale_trace_s {
  unsigned input_pages;
  unsigned output_pages;
  unsigned raise_events;
  unsigned reduce_events;
} cf_v2_pwg_scale_trace_t;

static const unsigned cf_v2_pwg_scale_dimensions[] = {
    1U, 2U, 3U, 4U, 7U, 8U, 15U, 16U, 31U, 32U,
};

static const unsigned cf_v2_pwg_scale_factors[] = {2U, 3U, 4U};

static const cf_v2_pwg_scale_format_t cf_v2_pwg_scale_input_formats[] = {
    {CUPS_CSPACE_K, 1U, 1U, 1U},
    {CUPS_CSPACE_W, 8U, 8U, 1U},
    {CUPS_CSPACE_SRGB, 8U, 24U, 3U},
};

static const cf_v2_pwg_scale_format_t cf_v2_pwg_scale_output_formats[] = {
    {CUPS_CSPACE_K, 1U, 1U, 1U},
    {CUPS_CSPACE_W, 8U, 8U, 1U},
    {CUPS_CSPACE_RGB, 8U, 24U, 3U},
    {CUPS_CSPACE_CMYK, 8U, 32U, 4U},
};

static void cf_v2_pwg_scale_log(void *data, cf_loglevel_t level,
                                const char *message, ...) {
  cf_v2_pwg_scale_trace_t *trace = (cf_v2_pwg_scale_trace_t *)data;

  (void)level;
  if (!trace || !message) {
    return;
  }
  if (getenv("CF_V2_TRACE_FILTER_LOG")) {
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    fputc('\n', stderr);
    va_end(args);
  }
  if (strstr(message, "Input page %d")) {
    trace->input_pages++;
  } else if (strstr(message, "Output page %d")) {
    trace->output_pages++;
  } else if (strstr(message, "Raising by factor %d")) {
    trace->raise_events++;
  } else if (strstr(message, "Reducing by factor %d")) {
    trace->reduce_events++;
  }
}

static int cf_v2_pwg_scale_not_canceled(void *data) {
  (void)data;
  return 0;
}

static void cf_v2_pwg_scale_close_fd(int *fd) {
  if (*fd >= 0) {
    if (fcntl(*fd, F_GETFD) >= 0 || errno != EBADF) {
      (void)close(*fd);
    }
    *fd = -1;
  }
}

static uint8_t cf_v2_pwg_scale_material(const uint8_t *material,
                                        size_t material_size,
                                        unsigned pattern, size_t offset) {
  uint8_t value = material_size
                      ? material[(offset + pattern * 257U) % material_size]
                      : (uint8_t)(offset * 131U + pattern * 67U);

  switch (pattern % 6U) {
    case 0:
      return value;
    case 1:
      return 0x00U;
    case 2:
      return 0xffU;
    case 3:
      return offset & 1U ? 0xaaU : 0x55U;
    case 4:
      return (uint8_t)(offset & 0xffU);
    default:
      return (uint8_t)(value ^ (uint8_t)(offset * 17U));
  }
}

static int cf_v2_pwg_scale_write_input(
    int fd, const uint8_t selector[CF_V2_PWG_SCALE_SELECTORS],
    const uint8_t *material, size_t material_size, unsigned width,
    unsigned height, unsigned x_dpi, unsigned y_dpi,
    unsigned page_width, unsigned page_height,
    const cf_v2_pwg_scale_format_t *format, unsigned pages) {
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  uint8_t *line = NULL;
  uint64_t bytes_per_line_64 =
      ((uint64_t)width * format->bits_per_pixel + 7U) / 8U;
  unsigned bytes_per_line;
  int ok = 0;

  if (!bytes_per_line_64 || bytes_per_line_64 > UINT32_MAX) {
    return 0;
  }
  bytes_per_line = (unsigned)bytes_per_line_64;
#ifdef CF_V2_PWG_RELATION_PROGRAM
  if (bytes_per_line > 512U * 1024U) {
#else
  if (bytes_per_line > 4096U) {
#endif
    return 0;
  }
  raster = cupsRasterOpen(fd, CUPS_RASTER_WRITE_PWG);
  line = (uint8_t *)malloc(bytes_per_line);
  if (!raster || !line) {
    goto done;
  }

  for (unsigned page = 0; page < pages; page++) {
    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "Plain", sizeof("Plain"));
    memcpy(header.cupsPageSizeName, "Tiny", sizeof("Tiny"));
    header.HWResolution[0] = x_dpi;
    header.HWResolution[1] = y_dpi;
    header.PageSize[0] = page_width;
    header.PageSize[1] = page_height;
    header.ImagingBoundingBox[2] = width;
    header.ImagingBoundingBox[3] = height;
    header.cupsPageSize[0] = (float)page_width;
    header.cupsPageSize[1] = (float)page_height;
    header.cupsImagingBBox[2] = header.cupsPageSize[0];
    header.cupsImagingBBox[3] = header.cupsPageSize[1];
    header.cupsWidth = width;
    header.cupsHeight = height;
    header.cupsBitsPerColor = format->bits_per_color;
    header.cupsBitsPerPixel = format->bits_per_pixel;
    header.cupsBytesPerLine = bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = format->color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = format->num_colors;
    header.NumCopies = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_CrossFeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_FeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] = width;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] = height;

    if (!cupsRasterWriteHeader2(raster, &header)) {
      goto done;
    }
    for (unsigned row = 0; row < height; row++) {
      for (unsigned column = 0; column < bytes_per_line; column++) {
        size_t offset = ((size_t)page * height + row) * bytes_per_line + column;
        line[column] = cf_v2_pwg_scale_material(
            material, material_size, selector[6] + selector[7], offset);
      }
      if (cupsRasterWritePixels(raster, line, bytes_per_line) !=
          bytes_per_line) {
        goto done;
      }
    }
  }
  ok = 1;

done:
  free(line);
  if (raster) {
    cupsRasterClose(raster);
  }
  return ok;
}

static int cf_v2_pwg_scale_write_ppd(
    FILE *stream, unsigned page_width, unsigned page_height,
    unsigned output_x_dpi, unsigned output_y_dpi,
    const cf_v2_pwg_scale_format_t *format, cups_order_t order) {
  const char *color_choice =
      format->color_space == CUPS_CSPACE_CMYK ? "CMYK" :
      (format->num_colors > 1U ? "RGB" : "Gray");

  return fprintf(
             stream,
             "*PPD-Adobe: \"4.3\"\n"
             "*FormatVersion: \"4.3\"\n"
             "*FileVersion: \"1.0\"\n"
             "*LanguageVersion: English\n"
             "*LanguageEncoding: ISOLatin1\n"
             "*Manufacturer: \"OpenPrinting\"\n"
             "*ModelName: \"PWG scale state\"\n"
             "*ShortNickName: \"PWG scale state\"\n"
             "*NickName: \"PWG scale state\"\n"
             "*PCFileName: \"PWGSCALE.PPD\"\n"
             "*Product: \"(PWG scale state)\"\n"
             "*PSVersion: \"(3010) 0\"\n"
             "*cupsVersion: 2.4\n"
             "*cupsFilter: \"application/vnd.cups-raster 0 pwgtoraster\"\n"
             "*OpenUI *PageSize/Page Size: PickOne\n"
             "*DefaultPageSize: Tiny\n"
             "*PageSize Tiny/Tiny: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n"
             "*CloseUI: *PageSize\n"
             "*OpenUI *PageRegion/Page Region: PickOne\n"
             "*DefaultPageRegion: Tiny\n"
             "*PageRegion Tiny/Tiny: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n"
             "*CloseUI: *PageRegion\n"
             "*DefaultImageableArea: Tiny\n"
             "*ImageableArea Tiny/Tiny: \"0 0 %u %u\"\n"
             "*DefaultPaperDimension: Tiny\n"
             "*PaperDimension Tiny/Tiny: \"%u %u\"\n"
             "*OpenUI *ColorModel/Color: PickOne\n"
             "*DefaultColorModel: %s\n"
             "*ColorModel %s/%s: \"<</cupsColorSpace %u/cupsColorOrder %u/cupsBitsPerColor %u/cupsBitsPerPixel %u/cupsNumColors %u>>setpagedevice\"\n"
             "*CloseUI: *ColorModel\n"
             "*OpenUI *Resolution/Resolution: PickOne\n"
             "*DefaultResolution: Testdpi\n"
             "*Resolution Testdpi/Test dpi: \"<</HWResolution[%u %u]>>setpagedevice\"\n"
             "*CloseUI: *Resolution\n",
             page_width, page_height, page_width, page_height, page_width,
             page_height, page_width, page_height,
             color_choice, color_choice, color_choice,
             (unsigned)format->color_space, (unsigned)order,
             format->bits_per_color,
             order == CUPS_ORDER_PLANAR ? format->bits_per_color
                                        : format->bits_per_pixel,
             format->num_colors,
             output_x_dpi,
             output_y_dpi) >= 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const size_t magic_size = sizeof(CF_V2_PWG_SCALE_MAGIC) - 1U;
  const uint8_t *selector;
  const uint8_t *material;
  const cf_v2_pwg_scale_format_t *input_format;
  const cf_v2_pwg_scale_format_t *output_format;
  char input_name[] = "/tmp/cupsfilters-v2-pwg-scale-input.XXXXXX";
  char ppd_name[] = "/tmp/cupsfilters-v2-pwg-scale-ppd.XXXXXX";
  char options_text[256];
  cf_filter_data_t filter_data;
  cf_v2_pwg_scale_trace_t trace;
  cups_option_t *options = NULL;
  unsigned base_width;
  unsigned base_height;
  unsigned x_factor;
  unsigned y_factor;
  unsigned input_width;
  unsigned input_height;
  unsigned input_x_dpi;
  unsigned input_y_dpi;
  unsigned output_x_dpi;
  unsigned output_y_dpi;
  unsigned output_width;
  unsigned output_height;
  unsigned input_page_width;
  unsigned input_page_height;
  unsigned ppd_page_width;
  unsigned ppd_page_height;
  unsigned relation_boundary = 0U;
  const char *color_choice;
  unsigned pages;
  cups_order_t output_order;
  size_t material_size;
  int input_fd = -1;
  int output_fd = -1;
  int ppd_fd = -1;
  int ppd_loaded = 0;
  int status = 1;

  if (!data || size < magic_size + CF_V2_PWG_SCALE_SELECTORS ||
      size > magic_size + CF_V2_PWG_SCALE_SELECTORS +
                 CF_V2_PWG_SCALE_MAX_MATERIAL ||
      memcmp(data, CF_V2_PWG_SCALE_MAGIC, magic_size) != 0) {
    return 0;
  }

  selector = data + magic_size;
  material = selector + CF_V2_PWG_SCALE_SELECTORS;
  material_size = size - magic_size - CF_V2_PWG_SCALE_SELECTORS;
  base_width = cf_v2_pwg_scale_dimensions[
      selector[0] % (sizeof(cf_v2_pwg_scale_dimensions) /
                     sizeof(cf_v2_pwg_scale_dimensions[0]))];
  base_height = cf_v2_pwg_scale_dimensions[
      selector[1] % (sizeof(cf_v2_pwg_scale_dimensions) /
                     sizeof(cf_v2_pwg_scale_dimensions[0]))];
  x_factor = cf_v2_pwg_scale_factors[
      selector[2] % (sizeof(cf_v2_pwg_scale_factors) /
                     sizeof(cf_v2_pwg_scale_factors[0]))];
  y_factor = cf_v2_pwg_scale_factors[
      selector[3] % (sizeof(cf_v2_pwg_scale_factors) /
                     sizeof(cf_v2_pwg_scale_factors[0]))];
  input_format = &cf_v2_pwg_scale_input_formats[
      selector[4] % (sizeof(cf_v2_pwg_scale_input_formats) /
                     sizeof(cf_v2_pwg_scale_input_formats[0]))];
  output_format = &cf_v2_pwg_scale_output_formats[
      (selector[4] >> 4U) % (sizeof(cf_v2_pwg_scale_output_formats) /
                             sizeof(cf_v2_pwg_scale_output_formats[0]))];
  output_order = (cups_order_t)(selector[5] % 3U);
  pages = 1U + ((selector[5] >> 4U) & 1U);

#ifdef CF_V2_PWG_SCALE_UP
  input_width = base_width;
  input_height = base_height;
  input_x_dpi = 72U;
  input_y_dpi = 72U;
  output_x_dpi = 72U * x_factor;
  output_y_dpi = 72U * y_factor;
  output_width = base_width * x_factor;
  output_height = base_height * y_factor;
#else
  input_width = base_width * x_factor;
  input_height = base_height * y_factor;
  input_x_dpi = 72U * x_factor;
  input_y_dpi = 72U * y_factor;
  output_x_dpi = 72U;
  output_y_dpi = 72U;
  output_width = base_width;
  output_height = base_height;
#endif

  input_page_width = base_width;
  input_page_height = base_height;
  ppd_page_width = base_width;
  ppd_page_height = base_height;

#ifdef CF_V2_PWG_RELATION_PROGRAM
  relation_boundary = selector[4] % 3U;
  pages = 1U;
  input_format = &cf_v2_pwg_scale_input_formats[1];
  output_format = &cf_v2_pwg_scale_output_formats[1];
  output_order = CUPS_ORDER_CHUNKED;
  input_width = 32U;
  input_height = 4U;
  input_x_dpi = 72U;
  input_y_dpi = 72U;
  output_x_dpi = 72U;
  output_y_dpi = 72U;
  output_width = 32U;
  output_height = 4U;
  input_page_width = 32U;
  input_page_height = 4U;
  ppd_page_width = 32U;
  ppd_page_height = 4U;

  if (relation_boundary == 1U) {
    input_width = 16U;
    input_height = 4U;
    output_width = 16U;
    output_height = 4U;
    input_page_width = 16U;
    ppd_page_width = 16U;
    output_format = &cf_v2_pwg_scale_output_formats[2];
    output_order = CUPS_ORDER_PLANAR;
  } else if (relation_boundary == 2U) {
#if CF_V2_PWG_RELATION_LANE == 1
    input_width = 447439U;
    input_height = 1U;
    input_x_dpi = 1U;
    input_y_dpi = 9600U;
    output_x_dpi = 9600U;
    output_y_dpi = 9600U;
    output_width = 76173U;
    output_height = 109054U;
    input_page_width = 612U;
    input_page_height = 792U;
    ppd_page_width = 595U;
    ppd_page_height = 842U;
#elif CF_V2_PWG_RELATION_LANE == 2
    input_width = 512U;
    input_height = 4U;
    input_x_dpi = 300U;
    input_y_dpi = 2516582700U;
    output_x_dpi = 300U;
    output_y_dpi = 300U;
    output_width = 2380U;
    output_height = 3408U;
    input_page_width = 612U;
    input_page_height = 792U;
    ppd_page_width = 595U;
    ppd_page_height = 842U;
#elif CF_V2_PWG_RELATION_LANE == 3
    input_width = 65536U;
    input_height = 1U;
    input_x_dpi = 72U;
    input_y_dpi = 72U;
    output_x_dpi = 72U;
    output_y_dpi = 72U;
    output_width = 65536U;
    output_height = 65536U;
    input_page_width = 65536U;
    input_page_height = 65536U;
    ppd_page_width = 65536U;
    ppd_page_height = 65536U;
    output_format = &cf_v2_pwg_scale_output_formats[2];
    output_order = CUPS_ORDER_PLANAR;
#endif
  }
#endif

  color_choice = output_format->color_space == CUPS_CSPACE_CMYK ? "CMYK" :
      (output_format->num_colors > 1U ? "RGB" : "Gray");

  cf_v2_init_runtime();
  memset(&filter_data, 0, sizeof(filter_data));
  memset(&trace, 0, sizeof(trace));
  input_fd = mkstemp(input_name);
  if (input_fd < 0) {
    goto cleanup;
  }
  unlink(input_name);
  if (!cf_v2_pwg_scale_write_input(
          input_fd, selector, material, material_size, input_width,
          input_height, input_x_dpi, input_y_dpi, input_page_width,
          input_page_height, input_format, pages) ||
      lseek(input_fd, 0, SEEK_SET) < 0) {
    goto cleanup;
  }

  output_fd = open("/dev/null", O_WRONLY);
  if (output_fd < 0) {
    goto cleanup;
  }
  ppd_fd = mkstemp(ppd_name);
  if (ppd_fd < 0) {
    goto cleanup;
  }
  {
    FILE *ppd_stream = fdopen(ppd_fd, "w");
    int ppd_ok;

    if (!ppd_stream) {
      goto cleanup;
    }
    ppd_fd = -1;
    ppd_ok = cf_v2_pwg_scale_write_ppd(
        ppd_stream, ppd_page_width, ppd_page_height, output_x_dpi,
        output_y_dpi, output_format, output_order);
    if (fclose(ppd_stream) != 0 || !ppd_ok) {
      goto cleanup;
    }
  }

  if (snprintf(options_text, sizeof(options_text),
               "PageSize=Tiny PageRegion=Tiny ColorModel=%s "
               "Resolution=Testdpi cm-calibration=true emit-jcl=false",
               color_choice) < 0) {
    goto cleanup;
  }
  filter_data.printer = (char *)"oss-fuzz-v2";
  filter_data.job_id = 1;
  filter_data.job_user = (char *)"fuzzer";
#ifdef CF_V2_PWG_RELATION_PROGRAM
  filter_data.job_title = (char *)"pwg-relation-program";
#elif defined(CF_V2_PWG_SCALE_UP)
  filter_data.job_title = (char *)"pwg-scale-up-state";
#else
  filter_data.job_title = (char *)"pwg-scale-down-state";
#endif
  filter_data.copies = 1;
  filter_data.content_type = (char *)"image/pwg-raster";
  filter_data.final_content_type =
      (char *)"application/vnd.cups-raster";
  filter_data.num_options = cupsParseOptions(options_text, 0, &options);
  filter_data.options = options;
  filter_data.back_pipe[0] = filter_data.back_pipe[1] = -1;
  filter_data.side_pipe[0] = filter_data.side_pipe[1] = -1;
  filter_data.logfunc = cf_v2_pwg_scale_log;
  filter_data.logdata = &trace;
  filter_data.iscanceledfunc = cf_v2_pwg_scale_not_canceled;

  if (ppdFilterLoadPPDFile(&filter_data, ppd_name) != 0) {
    goto cleanup;
  }
  ppd_loaded = 1;
  status = cfFilterPWGToRaster(input_fd, output_fd, 1, &filter_data, NULL);
  input_fd = -1;
  output_fd = -1;

  if (getenv("CF_V2_TRACE_STATE")) {
    fprintf(stderr,
            "pwg-scale status=%d input=%ux%u@%ux%u output=%ux%u@%ux%u "
            "factor=%ux%u input-mode=%u output-mode=%u order=%u pages=%u "
            "input-pages=%u output-pages=%u raise-events=%u "
            "reduce-events=%u\n",
            status, input_width, input_height, input_x_dpi, input_y_dpi,
            output_width, output_height, output_x_dpi, output_y_dpi, x_factor,
            y_factor, selector[4] % 3U, (selector[4] >> 4U) % 4U,
            (unsigned)output_order, pages, trace.input_pages,
            trace.output_pages, trace.raise_events, trace.reduce_events);
#ifdef CF_V2_PWG_RELATION_PROGRAM
    fprintf(stderr, "pwg-relation lane=%u boundary=%u\n",
            (unsigned)CF_V2_PWG_RELATION_LANE, relation_boundary);
#endif
  }

cleanup:
  cf_v2_pwg_scale_close_fd(&ppd_fd);
  cf_v2_pwg_scale_close_fd(&output_fd);
  cf_v2_pwg_scale_close_fd(&input_fd);
  if (filter_data.options) {
    cupsFreeOptions(filter_data.num_options, filter_data.options);
    filter_data.options = NULL;
  }
  if (ppd_loaded) {
    ppdFilterFreePPDFile(&filter_data);
  }
  unlink(ppd_name);
  return 0;
}
