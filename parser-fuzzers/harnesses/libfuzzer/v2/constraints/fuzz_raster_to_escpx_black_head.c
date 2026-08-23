// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerCustomMutator cf_v2_escpx_lut_base_mutator
#define LLVMFuzzerTestOneInput cf_v2_escpx_lut_base_test_one_input
#include "fuzz_raster_to_escpx_ppd_lut_bitplanes.c"
#undef LLVMFuzzerTestOneInput
#undef LLVMFuzzerCustomMutator

/*
 * cupsESCPBlack is applied after raster-derived row geometry has already
 * sized several buffers.  The continuation build maps only shrinking or
 * equal overrides; the boundary build also exposes the known #715 growth
 * predicate without weakening ASan or changing upstream code.
 */
#ifdef CF_V2_ESCPBLACK_BOUNDARY
#  define CF_V2_BLACK_MAGIC "ESCPBLD1"
#else
#  define CF_V2_BLACK_MAGIC "ESCPBLK1"
#endif

#define CF_V2_BLACK_MAGIC_SIZE 8U
#define CF_V2_BLACK_SELECTOR_SIZE 8U
#define CF_V2_BLACK_HEADER_SIZE \
  (CF_V2_BLACK_MAGIC_SIZE + CF_V2_BLACK_SELECTOR_SIZE)
#define CF_V2_BLACK_MAX_MATERIAL 1024U

typedef struct cf_v2_escpx_black_state_s
{
  cf_v2_escpx_lut_state_t raster;
  unsigned int header_row_count;
  unsigned int header_row_step;
  unsigned int override_row_count;
  unsigned int override_row_step;
  unsigned int override_mode;
} cf_v2_escpx_black_state_t;

static const cf_v2_escpx_lut_weave_t cf_v2_escpx_black_headers[] = {
  {3U, 1U, 1U, 1U},
  {4U, 0U, 1U, 1U},
  {4U, 1U, 2U, 1U},
  {4U, 0U, 2U, 2U}
};

static int
cf_v2_escpx_black_decode(const uint8_t *selector,
                         cf_v2_escpx_black_state_t *state)
{
  const cf_v2_escpx_lut_weave_t *header = &cf_v2_escpx_black_headers[
      selector[1] % (sizeof(cf_v2_escpx_black_headers) /
                     sizeof(cf_v2_escpx_black_headers[0]))];
  cf_v2_escpx_lut_state_t *raster;

  memset(state, 0, sizeof(*state));
  raster = &state->raster;
  raster->width = cf_v2_escpx_lut_widths[selector[0] %
      (sizeof(cf_v2_escpx_lut_widths) /
       sizeof(cf_v2_escpx_lut_widths[0]))];
  raster->lut_shape = 0U;
  raster->use_all_dither = 0U;
  raster->expected_bitplanes = 1U;
  raster->row_count = header->row_count;
  raster->row_feed = header->row_feed;
  raster->row_step = header->row_step;
  raster->column_step = header->column_step;
  raster->use_esci = selector[3] & 1U;
  raster->compression = selector[4] % 3U;
  raster->lifecycle = selector[5] % 3U;
  raster->material_schedule = selector[6] % 8U;
  raster->material_salt = selector[7];
  raster->bytes_per_line = raster->width;

  state->header_row_count = raster->row_count;
  state->header_row_step = raster->row_step;
  state->override_mode = selector[2] % 4U;
#ifdef CF_V2_ESCPBLACK_BOUNDARY
  switch (state->override_mode)
  {
    case 0U:
      state->override_row_count = state->header_row_count;
      state->override_row_step = state->header_row_step;
      break;
    case 1U:
      state->override_row_count = state->header_row_count - 1U;
      state->override_row_step = 1U;
      break;
    case 2U:
      state->override_row_count = 30U;
      state->override_row_step = 1U;
      break;
    default:
      state->override_row_count = 64U;
      state->override_row_step = 1U;
      break;
  }
#else
  switch (state->override_mode)
  {
    case 0U:
      state->override_row_count = state->header_row_count;
      state->override_row_step = state->header_row_step;
      break;
    case 1U:
      state->override_row_count = state->header_row_count - 1U;
      state->override_row_step = state->header_row_step;
      break;
    case 2U:
      state->override_row_count = 2U;
      state->override_row_step = 1U;
      break;
    default:
      state->override_row_count = state->header_row_count;
      state->override_row_step = 1U;
      break;
  }
#endif

  switch (raster->lifecycle)
  {
    case 0U:
      raster->height = state->override_row_count;
      break;
    case 1U:
      raster->height = state->override_row_count * state->override_row_step;
      break;
    default:
      raster->height = 2U * state->override_row_count *
                       state->override_row_step + state->override_row_step;
      break;
  }
  raster->height = cf_v2_escpx_lut_max(2U, raster->height);
  raster->height = cf_v2_escpx_lut_min(64U, raster->height);

  return raster->width % raster->column_step == 0U &&
         state->header_row_count >= 3U &&
         state->header_row_count <= 4U &&
         state->header_row_step >= 1U &&
         state->header_row_step <= 2U &&
         state->override_row_count >= 2U &&
         state->override_row_count <= 64U &&
         state->override_row_step >= 1U &&
         state->override_row_step <= 2U;
}

static int
cf_v2_escpx_black_write_ppd(const char *path,
                            const cf_v2_escpx_black_state_t *state)
{
  FILE *file;
  int result;

  if (!cf_v2_escpx_lut_write_ppd(path, &state->raster))
    return 0;
  file = fopen(path, "a");
  if (!file)
    return 0;
  result = fprintf(file, "*cupsESCPBlack 300dpi: \"%u %u\"\n",
                   state->override_row_count, state->override_row_step);
  if (fclose(file) != 0)
    return 0;
  return result > 0;
}

static int
cf_v2_escpx_black_verify_ppd(const char *path,
                             const cf_v2_escpx_black_state_t *state)
{
  ppd_file_t *ppd = ppdOpenFile(path);
  ppd_attr_t *attribute;
  unsigned int row_count = 0U;
  unsigned int row_step = 0U;
  int ok = 0;

  if (!ppd)
    return 0;
  attribute = ppdFindAttr(ppd, "cupsESCPBlack", "300dpi");
  if (attribute && attribute->value &&
      sscanf(attribute->value, "%u%u", &row_count, &row_step) == 2 &&
      row_count == state->override_row_count &&
      row_step == state->override_row_step &&
      ppdFindAttr(ppd, "cupsESCPOffsets", "300dpi") == NULL)
    ok = 1;
  ppdClose(ppd);
  return ok;
}

static int
cf_v2_escpx_black_run_filter(const char *ppd_path, const char *raster_path,
                             const cf_v2_escpx_black_state_t *state)
{
  cf_v2_escpx_lut_state_t effective = state->raster;
  char options[192];
  char *arguments[] = {
    (char *)"rastertoescpx", (char *)"1", (char *)"libfuzzer",
    (char *)CF_V2_BLACK_MAGIC, (char *)"1", options,
    (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  const int have_saved_sigterm =
      sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  const unsigned int expected_row_bytes =
      (state->raster.width / state->raster.column_step + 7U) / 8U;
  int status;

  effective.row_count = state->override_row_count;
  effective.row_step = state->override_row_step;
  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=Black MediaType=Plain "
           "Resolution=300dpi emit-jcl=false");
  if (!cf_v2_escpx_lut_install_environment(ppd_path))
    goto environment_done;

  cf_v2_escpx_lut_capture_size = 0U;
  cf_v2_escpx_lut_band_trace_count = 0U;
  cf_v2_escpx_lut_filter_ppd = NULL;
  srand(0x424c4143U);
  status = cf_v2_escpx_lut_rastertoescpx_main(7, arguments);
  cf_v2_escpx_lut_require(
      status == 0 && cf_v2_escpx_lut_filter_ppd != NULL &&
      PrinterPlanes == 1 && BitPlanes == 1 &&
      DotBufferSize == (int)expected_row_bytes &&
      DotRowCount == (int)state->override_row_count &&
      DotRowStep == (int)state->override_row_step &&
      DotColStep == (int)state->raster.column_step &&
      DotRowMax == (int)(state->header_row_count * state->header_row_step));

#ifndef CF_V2_ESCPBLACK_BOUNDARY
  cf_v2_escpx_lut_require(
      state->override_row_count <= state->header_row_count &&
      state->override_row_step <= state->header_row_step &&
      (state->raster.row_feed == 0U ? DotRowFeed >= 1 :
       DotRowFeed == (int)state->raster.row_feed));
  cf_v2_escpx_lut_verify_output(&effective);
#endif

  ppdClose(cf_v2_escpx_lut_filter_ppd);
  cf_v2_escpx_lut_filter_ppd = NULL;
  cf_v2_escpx_lut_reset_filter_globals();
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
  const size_t minimum = CF_V2_BLACK_HEADER_SIZE + 1U;
  const size_t maximum = CF_V2_BLACK_HEADER_SIZE + CF_V2_BLACK_MAX_MATERIAL;
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
  memcpy(data, CF_V2_BLACK_MAGIC, CF_V2_BLACK_MAGIC_SIZE);
  if ((seed & 3U) != 0U)
  {
    const size_t slot = CF_V2_BLACK_MAGIC_SIZE +
        ((seed >> 2U) % CF_V2_BLACK_SELECTOR_SIZE);
    data[slot] ^= (uint8_t)(1U + ((seed >> 10U) & 0xffU));
    return size;
  }
  material_size = LLVMFuzzerMutate(data + CF_V2_BLACK_HEADER_SIZE,
                                   size - CF_V2_BLACK_HEADER_SIZE,
                                   limit - CF_V2_BLACK_HEADER_SIZE);
  if (material_size == 0U)
  {
    data[CF_V2_BLACK_HEADER_SIZE] = (uint8_t)seed;
    material_size = 1U;
  }
  memcpy(data, CF_V2_BLACK_MAGIC, CF_V2_BLACK_MAGIC_SIZE);
  return CF_V2_BLACK_HEADER_SIZE + material_size;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/escpblk1-XXXXXX";
  char ppd_path[sizeof(directory) + 16U];
  char raster_path[sizeof(directory) + 16U];
  cf_v2_escpx_black_state_t state;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;

  if (!data || size < CF_V2_BLACK_HEADER_SIZE + 1U ||
      size > CF_V2_BLACK_HEADER_SIZE + CF_V2_BLACK_MAX_MATERIAL ||
      memcmp(data, CF_V2_BLACK_MAGIC, CF_V2_BLACK_MAGIC_SIZE) != 0)
    return 0;
  selector = data + CF_V2_BLACK_MAGIC_SIZE;
  material = data + CF_V2_BLACK_HEADER_SIZE;
  material_size = size - CF_V2_BLACK_HEADER_SIZE;
  if (!cf_v2_escpx_black_decode(selector, &state) || !mkdtemp(directory))
    return 0;

  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_escpx_black_write_ppd(ppd_path, &state) &&
      cf_v2_escpx_black_verify_ppd(ppd_path, &state) &&
      cf_v2_escpx_lut_write_raster(raster_path, &state.raster, material,
                                   material_size))
    (void)cf_v2_escpx_black_run_filter(ppd_path, raster_path, &state);

  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
  return 0;
}
