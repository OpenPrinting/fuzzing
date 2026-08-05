#define _GNU_SOURCE

#include <cupsfilters/image.h>
#include <cupsfilters/image-private.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(CUPSFILTERS_IMAGE_CODEC_JPEG)
#  include <jpeglib.h>
#  include <setjmp.h>
#elif defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
#  include <sys/types.h>
#  include <tiffio.h>
#endif

#if !defined(CUPSFILTERS_IMAGE_CODEC_JPEG) && \
    !defined(CUPSFILTERS_IMAGE_CODEC_TIFF) && \
    !defined(CUPSFILTERS_IMAGE_CODEC_PNG)
#  define CUPSFILTERS_IMAGE_CODEC_PNG
#endif

#ifndef CUPSFILTERS_IMAGE_CODEC_MAX_INPUT
#  define CUPSFILTERS_IMAGE_CODEC_MAX_INPUT (2U * 1024U * 1024U)
#endif

#define IMAGE_CODEC_MAX_DIMENSION 4096U
#define IMAGE_CODEC_MAX_DECODED (16U * 1024U * 1024U)
#define IMAGE_CODEC_MAX_SCANLINE (64U * 1024U)

#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
typedef struct tiff_read_state_s
{
  int active;
  uint8_t sentinel;
  unsigned failures;
  uint32_t first_failed_row;
} tiff_read_state_t;

static _Thread_local tiff_read_state_t tiff_read_state;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  TIFFSetErrorHandler(NULL);
  TIFFSetErrorHandlerExt(NULL);
  TIFFSetWarningHandler(NULL);
  TIFFSetWarningHandlerExt(NULL);
  return (0);
}

extern TIFF *__real_TIFFFdOpen(int fd, const char *name, const char *mode);
extern int __real_TIFFReadScanline(TIFF *tif, void *buffer, uint32_t row,
                                   uint16_t sample);

TIFF *
__wrap_TIFFFdOpen(int fd, const char *name, const char *mode)
{
  int duplicate = dup(fd);
  TIFF *tif;

  if (duplicate < 0)
    return (NULL);
  tif = __real_TIFFFdOpen(duplicate, name, mode);
  if (!tif)
    close(duplicate);
  return (tif);
}

int
__wrap_TIFFReadScanline(TIFF *tif, void *buffer, uint32_t row,
                        uint16_t sample)
{
  tmsize_t size;
  int result;

#if !defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_DISCOVERY) && \
    !defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_CONTINUATION)
  if (tiff_read_state.active && buffer)
  {
    size = TIFFScanlineSize(tif);
    if (size > 0 && size <= IMAGE_CODEC_MAX_SCANLINE)
      memset(buffer, tiff_read_state.sentinel, (size_t)size);
  }
#else
  (void)size;
#endif
  result = __real_TIFFReadScanline(tif, buffer, row, sample);
  if (tiff_read_state.active && result < 0)
  {
    if (!tiff_read_state.failures)
      tiff_read_state.first_failed_row = row;
    tiff_read_state.failures ++;
  }
  return (result);
}
#endif

static void
close_image(cf_image_t *image)
{
  cf_ic_t *cached[IMAGE_CODEC_MAX_DECODED /
                  (CF_TILE_SIZE * CF_TILE_SIZE)] = {0};
  unsigned cached_count = 0;
  unsigned x_tiles;
  unsigned y_tiles;

  if (!image)
    return;

  if (image->cachefile >= 0)
  {
    close(image->cachefile);
    unlink(image->cachename);
  }

  x_tiles = (image->xsize + CF_TILE_SIZE - 1) / CF_TILE_SIZE;
  y_tiles = (image->ysize + CF_TILE_SIZE - 1) / CF_TILE_SIZE;
  if (image->tiles && x_tiles <= IMAGE_CODEC_MAX_DIMENSION / CF_TILE_SIZE &&
      y_tiles <= IMAGE_CODEC_MAX_DIMENSION / CF_TILE_SIZE)
  {
    for (unsigned y = 0; y < y_tiles; y ++)
    {
      if (!image->tiles[y])
        continue;
      for (unsigned x = 0; x < x_tiles; x ++)
      {
        cf_ic_t *entry = image->tiles[y][x].ic;
        unsigned seen = 0;

        if (!entry)
          continue;
        while (seen < cached_count && cached[seen] != entry)
          seen ++;
        if (seen == cached_count &&
            cached_count < sizeof(cached) / sizeof(cached[0]))
          cached[cached_count ++] = entry;
      }
    }
  }

  for (unsigned i = 0; i < cached_count; i ++)
    free(cached[i]);
  if (image->tiles)
  {
    free(image->tiles[0]);
    free(image->tiles);
  }
  free(image);
}

static cf_image_t *
open_codec(FILE *fp, cf_icspace_t primary, cf_icspace_t secondary,
           int saturation, int hue, const cf_ib_t *lut)
{
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_DISCOVERY) || \
    defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_CONTINUATION)
  cf_image_t *image = cfImageOpenFP(fp, primary, secondary, saturation, hue,
                                    lut);

  /* TIFFFdOpen owns a duplicate fd; a successful decode leaves fp open. */
  if (image)
    (void)fclose(fp);
  return (image);
#else
  cf_image_t *image = (cf_image_t *)calloc(1, sizeof(cf_image_t));
  int status;

  if (!image)
  {
    fclose(fp);
    return (NULL);
  }

  image->cachefile = -1;
  image->max_ics = CF_TILE_MINIMUM;
  image->xppi = 200;
  image->yppi = 200;
#if defined(CUPSFILTERS_IMAGE_CODEC_JPEG)
  status = _cfImageReadJPEG(image, fp, primary, secondary, saturation, hue,
                            lut);
#elif defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
  status = _cfImageReadTIFF(image, fp, primary, secondary, saturation, hue,
                            lut);
  /* TIFFFdOpen receives a duplicate fd from the linker wrapper above. */
  if (!status)
    (void)fclose(fp);
#else
  status = _cfImageReadPNG(image, fp, primary, secondary, saturation, hue,
                           lut);
#endif
  if (status)
  {
    close_image(image);
    return (NULL);
  }

  return (image);
#endif
}

static uint32_t
read_be32(const uint8_t *data)
{
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) | data[3];
}

static uint32_t
hash_bytes(const uint8_t *data, size_t size)
{
  uint32_t hash = 2166136261U;

  for (size_t i = 0; i < size; i ++)
  {
    hash ^= data[i];
    hash *= 16777619U;
  }
  return (hash);
}

#if defined(CUPSFILTERS_IMAGE_CODEC_JPEG)
typedef struct jpeg_guard_s
{
  struct jpeg_error_mgr error;
  jmp_buf jump;
  JSAMPLE *row;
  int created;
} jpeg_guard_t;

extern struct jpeg_error_mgr *__real_jpeg_std_error(
    struct jpeg_error_mgr *error);

static void
jpeg_quiet_output(j_common_ptr cinfo)
{
  (void)cinfo;
}

static void
jpeg_quiet_emit(j_common_ptr cinfo, int message_level)
{
  if (message_level < 0)
    cinfo->err->num_warnings ++;
}

struct jpeg_error_mgr *
__wrap_jpeg_std_error(struct jpeg_error_mgr *error)
{
  struct jpeg_error_mgr *result = __real_jpeg_std_error(error);

  result->emit_message = jpeg_quiet_emit;
  result->output_message = jpeg_quiet_output;
  return (result);
}

static void
jpeg_guard_error_exit(j_common_ptr cinfo)
{
  jpeg_guard_t *guard = (jpeg_guard_t *)cinfo->err;

  longjmp(guard->jump, 1);
}

static int
valid_jpeg_budget(const uint8_t *data, size_t size)
{
  struct jpeg_decompress_struct *cinfo;
  jpeg_guard_t *guard;
  uint64_t decoded;
  size_t row_size;
  int valid = 0;

  if (size < 4 || data[0] != 0xff || data[1] != 0xd8 ||
      size > ULONG_MAX)
    return (0);

  cinfo = (struct jpeg_decompress_struct *)calloc(1, sizeof(*cinfo));
  guard = (jpeg_guard_t *)calloc(1, sizeof(*guard));
  if (!cinfo || !guard)
    goto cleanup;

  cinfo->err = jpeg_std_error(&guard->error);
  guard->error.error_exit = jpeg_guard_error_exit;
  if (setjmp(guard->jump))
    goto cleanup;

  jpeg_create_decompress(cinfo);
  guard->created = 1;
  jpeg_mem_src(cinfo, data, (unsigned long)size);
  if (jpeg_read_header(cinfo, TRUE) != JPEG_HEADER_OK ||
      (cinfo->num_components != 1 && cinfo->num_components != 3 &&
       cinfo->num_components != 4))
    goto cleanup;

  if (cinfo->num_components == 1)
    cinfo->out_color_space = JCS_GRAYSCALE;
  else if (cinfo->num_components == 4)
    cinfo->out_color_space = JCS_CMYK;
  else
    cinfo->out_color_space = JCS_RGB;
  jpeg_calc_output_dimensions(cinfo);
  decoded = (uint64_t)cinfo->output_width * cinfo->output_height *
            cinfo->num_components;
  if (!cinfo->output_width || !cinfo->output_height ||
      cinfo->output_width > IMAGE_CODEC_MAX_DIMENSION ||
      cinfo->output_height > IMAGE_CODEC_MAX_DIMENSION ||
      decoded > IMAGE_CODEC_MAX_DECODED)
    goto cleanup;

  if (!jpeg_start_decompress(cinfo) || !cinfo->output_components ||
      cinfo->output_width > SIZE_MAX / cinfo->output_components)
    goto cleanup;
  row_size = (size_t)cinfo->output_width * cinfo->output_components;
  guard->row = (JSAMPLE *)malloc(row_size);
  if (!guard->row)
    goto cleanup;

  while (cinfo->output_scanline < cinfo->output_height)
  {
    JSAMPROW row = guard->row;

    if (jpeg_read_scanlines(cinfo, &row, 1) != 1)
      goto cleanup;
  }
  if (!jpeg_finish_decompress(cinfo))
    goto cleanup;
  valid = 1;

cleanup:
  if (guard)
  {
    free(guard->row);
    if (guard->created)
      jpeg_destroy_decompress(cinfo);
  }
  free(guard);
  free(cinfo);
  return (valid);
}
#elif defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
static uint16_t
read_u16(const uint8_t *data, int little_endian)
{
  if (little_endian)
    return ((uint16_t)data[1] << 8) | data[0];
  return ((uint16_t)data[0] << 8) | data[1];
}

static uint32_t
read_u32(const uint8_t *data, int little_endian)
{
  if (little_endian)
    return ((uint32_t)data[3] << 24) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[1] << 8) | data[0];
  return read_be32(data);
}

static int
tiff_scalar(const uint8_t *data, size_t size, const uint8_t *entry,
            int little_endian, uint32_t *value)
{
  uint16_t type = read_u16(entry + 2, little_endian);
  uint32_t count = read_u32(entry + 4, little_endian);
  uint32_t offset;
  size_t element_size;

  if (!count)
    return (0);
  if (type == 3)
    element_size = 2;
  else if (type == 4)
    element_size = 4;
  else
    return (0);

  if (count <= 4 / element_size)
    offset = (uint32_t)(entry + 8 - data);
  else
    offset = read_u32(entry + 8, little_endian);
  if (offset > size || element_size > size - offset)
    return (0);

  *value = element_size == 2 ? read_u16(data + offset, little_endian)
                             : read_u32(data + offset, little_endian);
  return (1);
}

static int
valid_tiff_budget(const uint8_t *data, size_t size)
{
  uint32_t width = 0, height = 0, bits = 1, samples = 1;
  uint32_t photometric = UINT32_MAX, compression = UINT32_MAX;
  uint32_t planar = 1, orientation = 1;
  uint32_t seen_tags = 0;
  uint32_t ifd_offset;
  uint16_t count;
  int little_endian;

  if (size < 10)
    return (0);
  if (!memcmp(data, "II\x2a\x00", 4))
    little_endian = 1;
  else if (!memcmp(data, "MM\x00\x2a", 4))
    little_endian = 0;
  else
    return (0);

  ifd_offset = read_u32(data + 4, little_endian);
  if (ifd_offset > size - 2)
    return (0);
  count = read_u16(data + ifd_offset, little_endian);
  if (!count || count > 256 ||
      (size_t)count > (size - ifd_offset - 2) / 12)
    return (0);

  for (unsigned i = 0; i < count; i ++)
  {
    const uint8_t *entry = data + ifd_offset + 2 + i * 12;
    uint16_t tag = read_u16(entry, little_endian);
    uint32_t value;

    if (!tiff_scalar(data, size, entry, little_endian, &value))
      continue;
    switch (tag)
    {
      case 256 :
      case 257 :
      case 258 :
      case 259 :
      case 262 :
      case 274 :
      case 277 :
      case 284 :
      {
        unsigned bit = tag == 256 ? 0 : tag == 257 ? 1 : tag == 258 ? 2 :
                       tag == 259 ? 3 : tag == 262 ? 4 : tag == 274 ? 5 :
                       tag == 277 ? 6 : 7;

        if (seen_tags & (1U << bit))
          return (0);
        seen_tags |= 1U << bit;
        if (tag == 256)
          width = value;
        else if (tag == 257)
          height = value;
        else if (tag == 258)
          bits = value;
        else if (tag == 259)
          compression = value;
        else if (tag == 262)
          photometric = value;
        else if (tag == 274)
          orientation = value;
        else if (tag == 277)
          samples = value;
        else
          planar = value;
        break;
      }
      default : break;
    }
  }

  if (!width || !height || width > IMAGE_CODEC_MAX_DIMENSION ||
      height > IMAGE_CODEC_MAX_DIMENSION ||
      (bits != 1 && bits != 2 && bits != 4 && bits != 8) ||
      !samples || samples > 4 || (bits == 1 && samples > 1) ||
      planar == 2 || orientation < 1 || orientation > 4 ||
      (compression != 1 && compression != 5 && compression != 7 &&
       compression != 8 && compression != 32773 && compression != 32946))
    return (0);
  if (photometric != 0 && photometric != 1 && photometric != 2 &&
      photometric != 3 && photometric != 5)
    return (0);
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_DISCOVERY) || \
    defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_CONTINUATION)
  if ((photometric == 0 || photometric == 1) && samples > 4)
#else
  if ((photometric == 0 || photometric == 1) &&
      samples != 1 && samples != 2)
#endif
    return (0);
  if (photometric == 3 && samples != 1)
    return (0);
  if (photometric == 2 && samples != 3 && samples != 4)
    return (0);
#if !defined(CUPSFILTERS_IMAGE_CODEC_TIFF_PACKED_REGRESSION)
  /*
   * RGB2 is kept as an archived regression input. It otherwise terminates
   * every continuation worker at the known image-tiff.c packed-row OOB read.
   */
  if (photometric == 2 && bits == 2)
    return (0);
#endif
  if (photometric == 5 && samples != 4)
    return (0);
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF_GRAY_MULTISAMPLE_CONTINUATION)
  /*
   * Continue past the confirmed Gray8/SPP4 scanline overwrite while retaining
   * the adjacent grayscale layouts that the normal TIFF lane rejects.
   */
  if ((photometric != 0 && photometric != 1) || samples < 3 ||
      (bits == 8 && samples == 4))
    return (0);
#endif

  if (((uint64_t)width * bits * samples + 7U) / 8U >
      IMAGE_CODEC_MAX_SCANLINE)
    return (0);
  return ((uint64_t)width * height * 4U <= IMAGE_CODEC_MAX_DECODED);
}
#else
static int
valid_png_budget(const uint8_t *data, size_t size)
{
  static const uint8_t signature[8] =
      {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
  uint32_t width;
  uint32_t height;
  uint64_t row_bits;
  uint64_t decoded;
  unsigned bit_depth;
  unsigned color_type;
  unsigned channels;

  if (size < 33 || memcmp(data, signature, sizeof(signature)) ||
      read_be32(data + 8) != 13 || memcmp(data + 12, "IHDR", 4))
    return (0);

  width = read_be32(data + 16);
  height = read_be32(data + 20);
  bit_depth = data[24];
  color_type = data[25];
  if (!width || !height || width > IMAGE_CODEC_MAX_DIMENSION ||
      height > IMAGE_CODEC_MAX_DIMENSION || data[26] != 0 ||
      data[27] != 0 || data[28] > 1)
    return (0);

  switch (color_type)
  {
    case 0 :
        channels = 1;
        if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 &&
            bit_depth != 8 && bit_depth != 16)
          return (0);
        break;
    case 2 :
        channels = 3;
        if (bit_depth != 8 && bit_depth != 16)
          return (0);
        break;
    case 3 :
        channels = 1;
        if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 &&
            bit_depth != 8)
          return (0);
        break;
    case 4 :
        channels = 2;
        if (bit_depth != 8 && bit_depth != 16)
          return (0);
        break;
    case 6 :
        channels = 4;
        if (bit_depth != 8 && bit_depth != 16)
          return (0);
        break;
    default :
        return (0);
  }

  row_bits = (uint64_t)width * channels * bit_depth;
  decoded = ((row_bits + 7U) / 8U + 1U) * height;
  return (decoded <= IMAGE_CODEC_MAX_DECODED);
}
#endif

static int
valid_codec_budget(const uint8_t *data, size_t size)
{
#if defined(CUPSFILTERS_IMAGE_CODEC_JPEG)
  return (valid_jpeg_budget(data, size));
#elif defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
  return (valid_tiff_budget(data, size));
#else
  return (valid_png_budget(data, size));
#endif
}

static FILE *
open_input(const uint8_t *data, size_t size)
{
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
  FILE *fp = tmpfile();

  if (!fp)
    return (NULL);
  if (fwrite(data, 1, size, fp) != size || fflush(fp) || fseek(fp, 0, SEEK_SET))
  {
    fclose(fp);
    return (NULL);
  }
  return (fp);
#else
  return (fmemopen((void *)data, size, "rb"));
#endif
}

typedef struct codec_run_s
{
  uint32_t image_hash;
  unsigned scanline_failures;
  int decoded;
} codec_run_t;

static void
hash_pixels(uint32_t *hash, const cf_ib_t *pixels, size_t size)
{
  for (size_t i = 0; i < size; i ++)
  {
    *hash ^= pixels[i];
    *hash *= 16777619U;
  }
}

static codec_run_t
run_codec(const uint8_t *data, size_t size, uint32_t input_hash,
          uint8_t sentinel)
{
  static const cf_icspace_t primary_modes[] = {
      CF_IMAGE_RGB, CF_IMAGE_WHITE, CF_IMAGE_RGB_CMYK,
      CF_IMAGE_CMYK, CF_IMAGE_CMY};
  static const cf_icspace_t secondary_modes[] = {
      CF_IMAGE_WHITE, CF_IMAGE_RGB, CF_IMAGE_RGB,
      CF_IMAGE_RGB, CF_IMAGE_RGB};
  cf_image_t *image;
  cf_ib_t lut[256];
  cf_ib_t *row = NULL;
  cf_ib_t *column = NULL;
  FILE *fp;
  codec_run_t result = {2166136261U, 0, 0};
  unsigned width;
  unsigned height;
  unsigned depth;
  unsigned mode;
  unsigned rows[5];
  unsigned row_count = 3;
  size_t row_size;
  size_t column_size;

  mode = input_hash % (sizeof(primary_modes) / sizeof(primary_modes[0]));
  for (unsigned i = 0; i < sizeof(lut); i ++)
    lut[i] = (input_hash & 0x20U) ? (cf_ib_t)(255U - i) : (cf_ib_t)i;

  fp = open_input(data, size);
  if (!fp)
    return (result);

#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
  memset(&tiff_read_state, 0, sizeof(tiff_read_state));
  tiff_read_state.active = 1;
  tiff_read_state.sentinel = sentinel;
  tiff_read_state.first_failed_row = UINT32_MAX;
#else
  (void)sentinel;
#endif
  image = open_codec(fp, primary_modes[mode], secondary_modes[mode],
                     50 + (int)(input_hash % 151U),
                     (int)((input_hash >> 8) % 361U) - 180,
                     (input_hash & 0x40U) ? lut : NULL);
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
  tiff_read_state.active = 0;
  result.scanline_failures = tiff_read_state.failures;
#endif
  /* The selected codec owns and closes fp. */
  if (!image)
    return (result);
  result.decoded = 1;

  width = cfImageGetWidth(image);
  height = cfImageGetHeight(image);
  depth = (unsigned)cfImageGetDepth(image);
  if (!width || !height || !depth || width > IMAGE_CODEC_MAX_DIMENSION ||
      height > IMAGE_CODEC_MAX_DIMENSION ||
      (uint64_t)width * depth > IMAGE_CODEC_MAX_DECODED ||
      (uint64_t)height * depth > IMAGE_CODEC_MAX_DECODED)
    goto cleanup;

  row_size = (size_t)width * depth;
  column_size = (size_t)height * depth;
  row = (cf_ib_t *)malloc(row_size);
  column = (cf_ib_t *)malloc(column_size);
  if (!row || !column)
    goto cleanup;

  cfImageSetMaxTiles(image, 10 + (int)((input_hash >> 16) % 3U) * 8);
  rows[0] = 0;
  rows[1] = height / 2;
  rows[2] = height - 1;
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF)
  if (result.scanline_failures &&
      tiff_read_state.first_failed_row < height)
  {
    rows[row_count ++] = tiff_read_state.first_failed_row;
    rows[row_count ++] = height - 1 - tiff_read_state.first_failed_row;
  }
#endif
  hash_pixels(&result.image_hash, (const cf_ib_t *)&width, sizeof(width));
  hash_pixels(&result.image_hash, (const cf_ib_t *)&height, sizeof(height));
  hash_pixels(&result.image_hash, (const cf_ib_t *)&depth, sizeof(depth));
  for (unsigned i = 0; i < row_count; i ++)
  {
    memset(row, 0x3c, row_size);
    if (!cfImageGetRow(image, 0, (int)rows[i], (int)width, row))
      hash_pixels(&result.image_hash, row, row_size);
  }
  for (unsigned x_index = 0; x_index < 3; x_index ++)
  {
    unsigned x = x_index == 0 ? 0 : (x_index == 1 ? width / 2 : width - 1);

    memset(column, 0xc3, column_size);
    if (!cfImageGetCol(image, (int)x, 0, (int)height, column))
      hash_pixels(&result.image_hash, column, column_size);
  }

cleanup:
  free(column);
  free(row);
  close_image(image);
  return (result);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  codec_run_t first;
  uint32_t input_hash;

  if (!data || size > CUPSFILTERS_IMAGE_CODEC_MAX_INPUT ||
      !valid_codec_budget(data, size))
    return (0);

  input_hash = hash_bytes(data, size);
  first = run_codec(data, size, input_hash, 0xa5);
#if defined(CUPSFILTERS_IMAGE_CODEC_TIFF) && \
    defined(CUPSFILTERS_IMAGE_CODEC_TIFF_SCANLINE_ORACLE)
  if (first.scanline_failures)
  {
    codec_run_t second = run_codec(data, size, input_hash, 0x5a);

    if (first.decoded != second.decoded ||
        (first.decoded && second.decoded &&
         first.image_hash != second.image_hash))
      __builtin_trap();
  }
#endif
  return (0);
}
