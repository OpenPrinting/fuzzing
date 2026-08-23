// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * ESCPSTG1 state target: a coherent PPD + CUPS Raster continuation for the
 * rastertoescpx staggered-head route.
 *
 * Input:
 *   bytes 0..7   "ESCPSTG1"
 *   bytes 8..19  width, profile, command, compression, row-count, row-feed,
 *                row-step, column-step, offset-profile, lifecycle,
 *                material-schedule, material-salt selectors
 *   remaining    1..4096 bytes of cyclic raster material
 *
 * A build must define CF_V2_RASTERTOESCPX_SOURCE to the quoted,
 * current-upstream filter/rastertoescpx.c path and otherwise use the same
 * CUPS/libppd/libcupsfilters include and link closure as ESCPROW1.
 */

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/driver.h>
#include <ppd/ppd.h>

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CF_V2_RASTERTOESCPX_SOURCE
#error "CF_V2_RASTERTOESCPX_SOURCE must quote filter/rastertoescpx.c"
#endif

#define CF_V2_MAGIC "ESCPSTG1"
#define CF_V2_MAGIC_SIZE 8U
#define CF_V2_SELECTOR_SIZE 12U
#define CF_V2_HEADER_SIZE (CF_V2_MAGIC_SIZE + CF_V2_SELECTOR_SIZE)
#define CF_V2_MAX_MATERIAL 4096U
#define CF_V2_MAX_CAPTURE (1024U * 1024U)
#define CF_V2_MAX_BAND_TRACES 8192U

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

typedef struct cf_v2_state_s
{
  unsigned int width;
  unsigned int height;
  unsigned int planes;
  unsigned int use_esci;
  unsigned int compression;
  unsigned int row_count;
  unsigned int row_feed;
  unsigned int row_step;
  unsigned int column_step;
  unsigned int offset_profile;
  unsigned int lifecycle;
  unsigned int material_schedule;
  unsigned int material_salt;
  unsigned int bytes_per_line;
  int offsets[7];
} cf_v2_state_t;

typedef struct cf_v2_band_trace_s
{
  int x;
  int y;
  int plane;
  int count;
  int feed;
} cf_v2_band_trace_t;

static unsigned char cf_v2_capture[CF_V2_MAX_CAPTURE];
static size_t cf_v2_capture_size;
static cf_v2_band_trace_t cf_v2_band_traces[CF_V2_MAX_BAND_TRACES];
static size_t cf_v2_band_trace_count;
static ppd_file_t *cf_v2_filter_ppd;
static char cf_v2_ppd_env[
    sizeof("PPD=/tmp/escpstg1-XXXXXX/input.ppd")];
static char cf_v2_printer_env[] = "PRINTER=escpstg1";
static char cf_v2_content_type_env[] =
    "CONTENT_TYPE=application/vnd.cups-raster";
static int cf_v2_environment_installed;

static void
cf_v2_require(int condition)
{
  if (!condition)
    __builtin_trap();
}

static size_t
cf_v2_capture_bytes(const void *data, size_t size)
{
  cf_v2_require(size <= CF_V2_MAX_CAPTURE - cf_v2_capture_size);
  memcpy(cf_v2_capture + cf_v2_capture_size, data, size);
  cf_v2_capture_size += size;
  return size;
}

static int
cf_v2_capture_putchar(int value)
{
  const unsigned char byte = (unsigned char)value;

  (void)cf_v2_capture_bytes(&byte, 1U);
  return byte;
}

static int
cf_v2_capture_printf(const char *format, ...)
{
  char buffer[128];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  cf_v2_require(result >= 0 && (size_t)result < sizeof(buffer));
  (void)cf_v2_capture_bytes(buffer, (size_t)result);
  return result;
}

static int
cf_v2_trace_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;

  (void)stream;
  if (strncmp(format, "DEBUG: Printing band ", 21U) == 0)
  {
    cf_v2_band_trace_t *trace;

    cf_v2_require(cf_v2_band_trace_count < CF_V2_MAX_BAND_TRACES);
    trace = &cf_v2_band_traces[cf_v2_band_trace_count ++];
    va_start(arguments, format);
    (void)va_arg(arguments, void *);
    trace->x = va_arg(arguments, int);
    trace->y = va_arg(arguments, int);
    trace->plane = va_arg(arguments, int);
    trace->count = va_arg(arguments, int);
    trace->feed = va_arg(arguments, int);
    va_end(arguments);
  }
  return 0;
}

static int
cf_v2_quiet_fputs(const char *text, FILE *stream)
{
  (void)text;
  (void)stream;
  return 0;
}

static void
cf_v2_quiet_log(void *data, cf_loglevel_t level, const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static ppd_file_t *
cf_v2_filter_ppd_open(const char *path)
{
  cf_v2_filter_ppd = ppdOpenFile(path);
  return cf_v2_filter_ppd;
}

#undef cfWritePrintData
#define cfWritePrintData(data, size) cf_v2_capture_bytes((data), (size_t)(size))
#define putchar cf_v2_capture_putchar
#define printf cf_v2_capture_printf
#define fprintf cf_v2_trace_fprintf
#define fputs cf_v2_quiet_fputs
#define cfCUPSLogFunc cf_v2_quiet_log
#define ppdOpenFile cf_v2_filter_ppd_open
#define main cf_v2_rastertoescpx_main
#include CF_V2_RASTERTOESCPX_SOURCE
#undef main
#undef ppdOpenFile
#undef cfCUPSLogFunc
#undef fputs
#undef fprintf
#undef printf
#undef putchar
#undef cfWritePrintData

static const unsigned int cf_v2_widths[] = {24U, 48U, 96U, 192U};
static const unsigned int cf_v2_row_counts[] = {2U, 3U, 4U, 8U};
static const unsigned int cf_v2_row_feeds[] = {0U, 1U, 2U, 3U, 5U, 7U};
static const unsigned int cf_v2_steps[] = {1U, 2U, 3U, 4U};

static unsigned int
cf_v2_min(unsigned int left, unsigned int right)
{
  return left < right ? left : right;
}

static unsigned int
cf_v2_max(unsigned int left, unsigned int right)
{
  return left > right ? left : right;
}

static void
cf_v2_decode_offsets(cf_v2_state_t *state)
{
  const int step = (int)state->row_step;
  const int rows = (int)state->row_count;
  static const int controls[4] = {0, 0, 0, 0};
  int profile[4];
  unsigned int plane;

  switch (state->offset_profile)
  {
    case 0U :
        memcpy(profile, controls, sizeof(profile));
        break;
    case 1U :
        profile[0] = 0; profile[1] = 1; profile[2] = 2; profile[3] = 3;
        break;
    case 2U :
        profile[0] = 3; profile[1] = 2; profile[2] = 1; profile[3] = 0;
        break;
    case 3U :
        profile[0] = 0; profile[1] = 2; profile[2] = 1; profile[3] = 3;
        break;
    case 4U :
        profile[0] = 0; profile[1] = step;
        profile[2] = 2 * step; profile[3] = 3 * step;
        break;
    case 5U :
        profile[0] = 0; profile[1] = rows / 2;
        profile[2] = rows; profile[3] = 3 * rows / 2;
        break;
    case 6U :
        profile[0] = 0; profile[1] = 0;
        profile[2] = step; profile[3] = step;
        break;
    default :
        profile[0] = 3 * step; profile[1] = 0;
        profile[2] = 2 * step; profile[3] = step;
        break;
  }

  memset(state->offsets, 0, sizeof(state->offsets));
  for (plane = 0U; plane < 4U; plane ++)
    state->offsets[plane] = profile[plane];
}

static int
cf_v2_decode(const uint8_t *selector, cf_v2_state_t *state)
{
  unsigned int max_offset = 0U;
  unsigned int plane;

  memset(state, 0, sizeof(*state));
  state->width = cf_v2_widths[selector[0] %
      (sizeof(cf_v2_widths) / sizeof(cf_v2_widths[0]))];
  state->planes = (selector[1] & 1U) ? 6U : 4U;
  state->use_esci = selector[2] & 1U;
  state->compression = selector[3] % 3U;
  state->row_count = cf_v2_row_counts[selector[4] %
      (sizeof(cf_v2_row_counts) / sizeof(cf_v2_row_counts[0]))];
  state->row_feed = cf_v2_row_feeds[selector[5] %
      (sizeof(cf_v2_row_feeds) / sizeof(cf_v2_row_feeds[0]))];
  state->row_step = cf_v2_steps[selector[6] %
      (sizeof(cf_v2_steps) / sizeof(cf_v2_steps[0]))];
  state->column_step = cf_v2_steps[selector[7] %
      (sizeof(cf_v2_steps) / sizeof(cf_v2_steps[0]))];
  state->offset_profile = selector[8] % 8U;
  state->lifecycle = selector[9] % 4U;
  state->material_schedule = selector[10] % 8U;
  state->material_salt = selector[11];
  state->bytes_per_line = state->width * 4U;
  cf_v2_decode_offsets(state);

  for (plane = 0U; plane < state->planes; plane ++)
    max_offset = cf_v2_max(max_offset, (unsigned int)state->offsets[plane]);

  switch (state->lifecycle)
  {
    case 0U :
        state->height = cf_v2_max(2U, state->row_step);
        break;
    case 1U :
        state->height = state->row_count * state->row_step;
        break;
    case 2U :
        state->height = 4U * state->row_count * state->row_step +
                        state->row_step;
        break;
    default :
        state->height = 8U * state->row_count * state->row_step +
                        max_offset + 1U;
        break;
  }
  state->height = cf_v2_max(2U, cf_v2_min(state->height, 128U));

  return state->width % state->column_step == 0U &&
         state->row_step * state->column_step <= 16U;
}

static unsigned char
cf_v2_material(const uint8_t *material, size_t material_size,
               unsigned int row, unsigned int offset, unsigned int salt)
{
  return (unsigned char)(material[((size_t)row * 257U + offset + salt) %
                                  material_size] ^
                         (unsigned char)(row * 31U + offset * 17U + salt));
}

static int
cf_v2_dirty_row(const cf_v2_state_t *state, unsigned int row)
{
  switch (state->material_schedule)
  {
    case 0U : return 0;
    case 1U : return 1;
    case 2U : return (row & 1U) != 0U;
    case 3U : return row >= state->height / 2U;
    case 4U : return row < cf_v2_max(1U, state->height / 2U);
    case 5U :
        return row + 1U == cf_v2_min(state->height, state->row_count) ||
               row + 1U == state->height;
    case 6U : return 1;
    default : return (row + state->material_salt) % 3U != 0U;
  }
}

static void
cf_v2_fill_row(unsigned char *row, const cf_v2_state_t *state,
               const uint8_t *material, size_t material_size,
               unsigned int row_number)
{
  unsigned int pixel;

  memset(row, 0, state->bytes_per_line);
  if (!cf_v2_dirty_row(state, row_number))
    return;

  for (pixel = 0U; pixel < state->width; pixel ++)
  {
    unsigned int channel;
    unsigned char value = (unsigned char)(0xc0U |
        (cf_v2_material(material, material_size, row_number, pixel,
                        state->material_salt) & 0x3fU));

    if (state->material_schedule == 6U)
    {
      channel = (row_number + state->material_salt) % 4U;
      row[4U * pixel + channel] = value;
    }
    else
    {
      for (channel = 0U; channel < 4U; channel ++)
        row[4U * pixel + channel] = (unsigned char)(value ^
            (unsigned char)(channel * 0x11U));
    }
  }
}

static int
cf_v2_write_raster(const char *path, const cf_v2_state_t *state,
                   const uint8_t *material, size_t material_size)
{
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  unsigned char *row = NULL;
  unsigned int row_number;
  int descriptor = -1;
  int ok = 0;

  descriptor = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (descriptor < 0)
    return 0;
  raster = cupsRasterOpen(descriptor, CUPS_RASTER_WRITE);
  if (!raster)
    goto done;
  row = (unsigned char *)malloc(state->bytes_per_line);
  if (!row)
    goto done;

  memset(&header, 0, sizeof(header));
  memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
  memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
  memcpy(header.cupsPageSizeName, "Letter", sizeof("Letter"));
  header.HWResolution[0] = 300U;
  header.HWResolution[1] = 300U;
  header.PageSize[0] = 612U;
  header.PageSize[1] = 792U;
  header.cupsPageSize[0] = 612.0f;
  header.cupsPageSize[1] = 792.0f;
  header.ImagingBoundingBox[2] = 612U;
  header.ImagingBoundingBox[3] = 792U;
  header.cupsImagingBBox[2] = 612.0f;
  header.cupsImagingBBox[3] = 792.0f;
  header.cupsWidth = state->width;
  header.cupsHeight = state->height;
  header.cupsBitsPerColor = 8U;
  header.cupsBitsPerPixel = 32U;
  header.cupsBytesPerLine = state->bytes_per_line;
  header.cupsColorOrder = CUPS_ORDER_CHUNKED;
  header.cupsColorSpace = CUPS_CSPACE_CMYK;
  header.cupsCompression = state->compression;
  header.cupsRowCount = state->row_count;
  header.cupsRowFeed = state->row_feed;
  header.cupsRowStep = state->column_step * 100U + state->row_step;
  header.cupsNumColors = 4U;
  header.NumCopies = 1U;

  if (!cupsRasterWriteHeader2(raster, &header))
    goto done;
  for (row_number = 0U; row_number < state->height; row_number ++)
  {
    cf_v2_fill_row(row, state, material, material_size, row_number);
    if (cupsRasterWritePixels(raster, row, state->bytes_per_line) !=
        state->bytes_per_line)
      goto done;
  }
  ok = 1;

done:
  free(row);
  if (raster)
    cupsRasterClose(raster);
  if (descriptor >= 0)
    close(descriptor);
  return ok;
}

static int
cf_v2_write_ppd(const char *path, const cf_v2_state_t *state)
{
  const unsigned int model_number = ESCP_STAGGER |
      (state->use_esci ? ESCP_RASTER_ESCI : 0U);
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
      "*ModelName: \"ESCPSTG1\"\n"
      "*ShortNickName: \"ESCPSTG1\"\n"
      "*NickName: \"ESCPSTG1 staggered head\"\n"
      "*PCFileName: \"ESCPSTG.PPD\"\n"
      "*Product: \"(ESCPSTG1)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 1.0\n"
      "*cupsModelNumber: %u\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 rastertoescpx\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Letter\n"
      "*PageSize Letter/Letter: "
      "\"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
      "*PageSize A4/A4: "
      "\"<</PageSize[595 842]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*DefaultImageableArea: Letter\n"
      "*ImageableArea Letter/Letter: \"18 36 594 756\"\n"
      "*ImageableArea A4/A4: \"12 12 583 830\"\n"
      "*DefaultPaperDimension: Letter\n"
      "*PaperDimension Letter/Letter: \"612 792\"\n"
      "*PaperDimension A4/A4: \"595 842\"\n"
      "*OpenUI *ColorModel/Color: PickOne\n"
      "*DefaultColorModel: CMYK\n"
      "*ColorModel CMYK/CMYK: "
      "\"<</cupsColorSpace 6/cupsColorOrder 0/cupsBitsPerColor 8/"
      "cupsBitsPerPixel 32>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *MediaType/Media Type: PickOne\n"
      "*DefaultMediaType: Plain\n"
      "*MediaType Plain/Plain: \"<</MediaType(PLAIN)>>setpagedevice\"\n"
      "*CloseUI: *MediaType\n"
      "*OpenUI *Resolution/Resolution: PickOne\n"
      "*DefaultResolution: 300dpi\n"
      "*Resolution 300dpi/300 dpi: "
      "\"<</HWResolution[300 300]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n"
      "*cupsInkChannels: \"%u\"\n"
      "*cupsAllGamma: \"1.0 1.0\"\n"
      "*cupsAllXY: \"0 0\"\n"
      "*cupsAllXY: \"1 1\"\n"
      "*cupsESCPOffsets 300dpi: \"%d %d %d %d\"\n",
      model_number, state->planes, state->offsets[0], state->offsets[1],
      state->offsets[2], state->offsets[3]);
  if (fclose(file) != 0)
    return 0;
  return result >= 0;
}

static int
cf_v2_verify_ppd(const char *path, const cf_v2_state_t *state)
{
  ppd_file_t *ppd = ppdOpenFile(path);
  ppd_attr_t *attribute;
  int parsed[4];
  char extra;
  unsigned int plane;
  int ok = 0;

  if (!ppd)
    return 0;
  attribute = ppdFindAttr(ppd, "cupsESCPOffsets", "300dpi");
  if (!attribute || !attribute->value ||
      sscanf(attribute->value, "%d %d %d %d %c", &parsed[0], &parsed[1],
             &parsed[2], &parsed[3], &extra) != 4)
    goto done;
  for (plane = 0U; plane < 4U; plane ++)
    if (parsed[plane] != state->offsets[plane])
      goto done;
  attribute = ppdFindAttr(ppd, "cupsInkChannels", NULL);
  if (!attribute || !attribute->value ||
      (unsigned int)atoi(attribute->value) != state->planes ||
      !(ppd->model_number & ESCP_STAGGER) ||
      !!(ppd->model_number & ESCP_RASTER_ESCI) != !!state->use_esci)
    goto done;
  ok = 1;

done:
  ppdClose(ppd);
  return ok;
}

static int
cf_v2_install_environment(const char *ppd_path)
{
  int length = snprintf(cf_v2_ppd_env, sizeof(cf_v2_ppd_env), "PPD=%s",
                        ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_ppd_env))
    return 0;
  if (cf_v2_environment_installed)
    return 1;
  if (putenv(cf_v2_ppd_env) != 0 || putenv(cf_v2_printer_env) != 0 ||
      putenv(cf_v2_content_type_env) != 0)
    return 0;
  cf_v2_environment_installed = 1;
  return 1;
}

static int
cf_v2_color_code(unsigned int planes, int plane)
{
  static const int cmyk[4] = {2, 1, 4, 0};
  static const int light_cmyk[6] = {2, 18, 1, 17, 4, 0};

  cf_v2_require(plane >= 0 && (unsigned int)plane < planes);
  return planes == 4U ? cmyk[plane] : light_cmyk[plane];
}

static size_t
cf_v2_decode_packbits(size_t position, size_t expected_size)
{
  size_t decoded = 0U;

  while (decoded < expected_size)
  {
    unsigned int control;
    size_t count;

    cf_v2_require(position < cf_v2_capture_size);
    control = cf_v2_capture[position ++];
    if (control <= 127U)
    {
      count = (size_t)control + 1U;
      cf_v2_require(count <= expected_size - decoded &&
                    count <= cf_v2_capture_size - position);
      position += count;
    }
    else
    {
      cf_v2_require(control >= 129U && position < cf_v2_capture_size);
      count = 257U - control;
      cf_v2_require(count <= expected_size - decoded);
      position ++;
    }
    decoded += count;
  }
  cf_v2_require(decoded == expected_size);
  return position;
}

static size_t
cf_v2_verify_graphics(size_t position, const cf_v2_state_t *state,
                      const cf_v2_band_trace_t *trace)
{
  size_t cursor = position + 1U;
  size_t row_bytes = (state->width / state->column_step + 7U) / 8U;
  size_t expected_payload;
  unsigned int compression;
  unsigned int rows;
  unsigned int encoded_row_bytes;
  unsigned int offset = 0U;
  int color = cf_v2_color_code(state->planes, trace->plane);

  cf_v2_require(position < cf_v2_capture_size &&
                cf_v2_capture[position] == '\r');
  if (trace->x != 0)
  {
    static const unsigned char prefix[7] = {'\033', '(', '\\', 4, 0, 0xa0, 5};

    cf_v2_require(cursor + 9U <= cf_v2_capture_size &&
                  memcmp(cf_v2_capture + cursor, prefix, sizeof(prefix)) == 0);
    offset = (unsigned int)cf_v2_capture[cursor + 7U] |
             (unsigned int)cf_v2_capture[cursor + 8U] << 8U;
    cursor += 9U;
  }
  cf_v2_require(offset == (unsigned int)trace->x &&
                offset < state->column_step);

  if (state->use_esci)
  {
    cf_v2_require(cursor + 9U <= cf_v2_capture_size &&
                  cf_v2_capture[cursor] == '\033' &&
                  cf_v2_capture[cursor + 1U] == 'i' &&
                  cf_v2_capture[cursor + 2U] == (unsigned char)color &&
                  cf_v2_capture[cursor + 4U] == 1U);
    compression = cf_v2_capture[cursor + 3U];
    encoded_row_bytes = (unsigned int)cf_v2_capture[cursor + 5U] |
                        (unsigned int)cf_v2_capture[cursor + 6U] << 8U;
    rows = (unsigned int)cf_v2_capture[cursor + 7U] |
           (unsigned int)cf_v2_capture[cursor + 8U] << 8U;
    cursor += 9U;
  }
  else
  {
    if (color & 0x10)
    {
      static const unsigned char color_prefix[6] = {'\033', '(', 'r', 2, 0, 1};

      cf_v2_require(cursor + 7U <= cf_v2_capture_size &&
                    memcmp(cf_v2_capture + cursor, color_prefix,
                           sizeof(color_prefix)) == 0 &&
                    cf_v2_capture[cursor + 6U] ==
                        (unsigned char)(color & 0x0f));
      cursor += 7U;
    }
    else
    {
      cf_v2_require(cursor + 3U <= cf_v2_capture_size &&
                    cf_v2_capture[cursor] == '\033' &&
                    cf_v2_capture[cursor + 1U] == 'r' &&
                    cf_v2_capture[cursor + 2U] == (unsigned char)color);
      cursor += 3U;
    }
    cf_v2_require(cursor + 8U <= cf_v2_capture_size &&
                  cf_v2_capture[cursor] == '\033' &&
                  cf_v2_capture[cursor + 1U] == '.' &&
                  cf_v2_capture[cursor + 3U] ==
                      (unsigned char)(12U * state->row_step) &&
                  cf_v2_capture[cursor + 4U] ==
                      (unsigned char)(12U * state->column_step));
    compression = cf_v2_capture[cursor + 2U];
    rows = cf_v2_capture[cursor + 5U];
    encoded_row_bytes = ((unsigned int)cf_v2_capture[cursor + 6U] |
                         (unsigned int)cf_v2_capture[cursor + 7U] << 8U) / 8U;
    cf_v2_require((((unsigned int)cf_v2_capture[cursor + 6U] |
                    (unsigned int)cf_v2_capture[cursor + 7U] << 8U) % 8U) == 0U);
    cursor += 8U;
  }

  cf_v2_require((compression == '0' || compression == '1') &&
                encoded_row_bytes == row_bytes && rows >= 1U &&
                rows <= state->row_count && rows == (unsigned int)trace->count);
  expected_payload = row_bytes * rows;
  cf_v2_require(expected_payload > 0U &&
                expected_payload <= ((192U + 7U) / 8U) * 8U);
  if (compression == '0')
  {
    cf_v2_require(expected_payload <= cf_v2_capture_size - cursor);
    cursor += expected_payload;
  }
  else
    cursor = cf_v2_decode_packbits(cursor, expected_payload);
  return cursor;
}

static void
cf_v2_verify_output(const cf_v2_state_t *state)
{
  static const unsigned char feed_prefix[5] = {'\033', '(', 'v', 2, 0};
  size_t position = 0U;
  size_t trace_index = 0U;
  unsigned int pending_feed = 0U;
  unsigned int feed_records = 0U;

  while (position < cf_v2_capture_size)
  {
    if (position + 5U <= cf_v2_capture_size &&
        memcmp(cf_v2_capture + position, feed_prefix,
               sizeof(feed_prefix)) == 0)
    {
      cf_v2_require(!pending_feed && position + 8U <= cf_v2_capture_size);
      pending_feed = (unsigned int)cf_v2_capture[position + 5U] |
                     (unsigned int)cf_v2_capture[position + 6U] << 8U;
      cf_v2_require(pending_feed > 0U &&
                    cf_v2_capture[position + 7U] == '\r');
      feed_records ++;
      position += 7U;
      continue;
    }
    if (cf_v2_capture[position] == '\r')
    {
      const cf_v2_band_trace_t *trace;
      unsigned int expected_feed;

      cf_v2_require(trace_index < cf_v2_band_trace_count);
      trace = &cf_v2_band_traces[trace_index ++];
      expected_feed = trace->feed > 0 ? (unsigned int)trace->feed : 0U;
      cf_v2_require(pending_feed == expected_feed && trace->plane >= 0 &&
                    (unsigned int)trace->plane < state->planes &&
                    trace->count >= 1 &&
                    (unsigned int)trace->count <= state->row_count);
      pending_feed = 0U;
      position = cf_v2_verify_graphics(position, state, trace);
      continue;
    }
    cf_v2_require(!pending_feed);
    position ++;
  }

  cf_v2_require(!pending_feed && trace_index == cf_v2_band_trace_count &&
                cf_v2_capture_size >= 3U &&
                cf_v2_capture[cf_v2_capture_size - 3U] == 12U &&
                cf_v2_capture[cf_v2_capture_size - 2U] == '\033' &&
                cf_v2_capture[cf_v2_capture_size - 1U] == '@');
  if (state->material_schedule != 0U)
    cf_v2_require(trace_index > 0U);
  if (state->material_schedule != 0U && state->lifecycle >= 2U)
    cf_v2_require(feed_records > 0U);
}

static void
cf_v2_reset_filter_globals(void)
{
  RGB = NULL;
  CMYK = NULL;
  PixelBuffer = NULL;
  CMYKBuffer = NULL;
  InputBuffer = NULL;
  CompBuffer = NULL;
  memset(OutputBuffers, 0, sizeof(OutputBuffers));
  memset(DotBuffers, 0, sizeof(DotBuffers));
  memset(DotBands, 0, sizeof(DotBands));
  memset(DitherLuts, 0, sizeof(DitherLuts));
  memset(DitherStates, 0, sizeof(DitherStates));
  DotAvailList = NULL;
  DotUsedList = NULL;
  PrinterPlanes = 0;
  BitPlanes = 0;
  Canceled = 0;
}

static int
cf_v2_run_filter(const char *ppd_path, const char *raster_path,
                 const cf_v2_state_t *state)
{
  char options[192];
  char *arguments[] = {
    (char *)"rastertoescpx", (char *)"1", (char *)"libfuzzer",
    (char *)"ESCPSTG1", (char *)"1", options, (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  int have_saved_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  unsigned int plane;
  int status;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=CMYK MediaType=Plain "
           "Resolution=300dpi emit-jcl=false");
  if (!cf_v2_install_environment(ppd_path))
    goto environment_done;

  cf_v2_capture_size = 0U;
  cf_v2_band_trace_count = 0U;
  cf_v2_filter_ppd = NULL;
  srand(0x45534350U);
  status = cf_v2_rastertoescpx_main(7, arguments);
  cf_v2_require(status == 0 && cf_v2_filter_ppd != NULL &&
                (unsigned int)PrinterPlanes == state->planes &&
                BitPlanes == 1);
  for (plane = 0U; plane < state->planes; plane ++)
    cf_v2_require(DotRowOffset[plane] == state->offsets[plane]);
  cf_v2_verify_output(state);

  ppdClose(cf_v2_filter_ppd);
  cf_v2_filter_ppd = NULL;
  cf_v2_reset_filter_globals();
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return 1;

environment_done:
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return 0;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t minimum = CF_V2_HEADER_SIZE + 1U;
  const size_t maximum = CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL;
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
  memcpy(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE);

  if ((seed & 3U) != 0U)
  {
    size_t slot = CF_V2_MAGIC_SIZE +
                  ((seed >> 2U) % CF_V2_SELECTOR_SIZE);
    uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      data[slot] ^= delta;
    else
      data[slot] += delta;
    return size;
  }

  material_size = LLVMFuzzerMutate(data + CF_V2_HEADER_SIZE,
                                   size - CF_V2_HEADER_SIZE,
                                   limit - CF_V2_HEADER_SIZE);
  if (material_size == 0U)
  {
    data[CF_V2_HEADER_SIZE] = (uint8_t)seed;
    material_size = 1U;
  }
  memcpy(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE);
  return CF_V2_HEADER_SIZE + material_size;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/escpstg1-XXXXXX";
  char ppd_path[sizeof(directory) + 16U];
  char raster_path[sizeof(directory) + 16U];
  cf_v2_state_t state;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;

  if (!data || size < CF_V2_HEADER_SIZE + 1U ||
      size > CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL ||
      memcmp(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE) != 0)
    return 0;
  selector = data + CF_V2_MAGIC_SIZE;
  material = data + CF_V2_HEADER_SIZE;
  material_size = size - CF_V2_HEADER_SIZE;
  if (!cf_v2_decode(selector, &state) || !mkdtemp(directory))
    return 0;

  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_write_ppd(ppd_path, &state) &&
      cf_v2_verify_ppd(ppd_path, &state) &&
      cf_v2_write_raster(raster_path, &state, material, material_size))
    (void)cf_v2_run_filter(ppd_path, raster_path, &state);

  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
  return 0;
}
