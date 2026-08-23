// SPDX-License-Identifier: Apache-2.0
#include "../include/control.h"
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>

#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
#include <cupsfilters/pdfutils-private.h>
#include <fontconfig/fontconfig.h>
#include <sanitizer/lsan_interface.h>

#define CF_V2_TEXTTOPDF_TRACKED 1024U

static int cf_v2_texttopdf_active;
static _cf_pdf_out_t *cf_v2_texttopdf_pdf;
static _cf_fontembed_emb_params_t *
    cf_v2_texttopdf_fonts[CF_V2_TEXTTOPDF_TRACKED];
static size_t cf_v2_texttopdf_font_count;
static char *cf_v2_texttopdf_strdups[CF_V2_TEXTTOPDF_TRACKED];
static size_t cf_v2_texttopdf_strdup_count;

extern _cf_pdf_out_t *__real__cfPDFOutNew(void);
extern void __real__cfPDFOutFree(_cf_pdf_out_t *pdf);
extern _cf_fontembed_emb_params_t *__real__cfFontEmbedEmbNew(
    _cf_fontembed_fontfile_t *font, _cf_fontembed_emb_dest_t dest,
    _cf_fontembed_emb_constraint_t mode);
extern void __real__cfFontEmbedEmbClose(_cf_fontembed_emb_params_t *emb);
extern FcBool __real_FcInit(void);
extern char *__real_strdup(const char *value);
extern void __real_free(void *pointer);

FcBool __wrap_FcInit(void) {
  FcBool result;

  __lsan_disable();
  result = __real_FcInit();
  __lsan_enable();
  return result;
}

char *__wrap_strdup(const char *value) {
  char *copy = __real_strdup(value);

  if (cf_v2_texttopdf_active && copy &&
      cf_v2_texttopdf_strdup_count < CF_V2_TEXTTOPDF_TRACKED) {
    cf_v2_texttopdf_strdups[cf_v2_texttopdf_strdup_count++] = copy;
  }
  return copy;
}

static void cf_v2_texttopdf_forget_strdup(void *pointer) {
  for (size_t index = 0; index < cf_v2_texttopdf_strdup_count; index++) {
    if (cf_v2_texttopdf_strdups[index] != pointer) {
      continue;
    }
    cf_v2_texttopdf_strdups[index] =
        cf_v2_texttopdf_strdups[--cf_v2_texttopdf_strdup_count];
    return;
  }
}

_cf_fontembed_emb_params_t *__wrap__cfFontEmbedEmbNew(
    _cf_fontembed_fontfile_t *font, _cf_fontembed_emb_dest_t dest,
    _cf_fontembed_emb_constraint_t mode) {
  _cf_fontembed_emb_params_t *emb =
      __real__cfFontEmbedEmbNew(font, dest, mode);

  if (cf_v2_texttopdf_active && emb &&
      cf_v2_texttopdf_font_count < CF_V2_TEXTTOPDF_TRACKED) {
    cf_v2_texttopdf_fonts[cf_v2_texttopdf_font_count++] = emb;
  }
  return emb;
}

void __wrap__cfFontEmbedEmbClose(_cf_fontembed_emb_params_t *emb) {
  for (size_t index = 0; index < cf_v2_texttopdf_font_count; index++) {
    if (cf_v2_texttopdf_fonts[index] != emb) {
      continue;
    }
    cf_v2_texttopdf_fonts[index] =
        cf_v2_texttopdf_fonts[--cf_v2_texttopdf_font_count];
    break;
  }
  __real__cfFontEmbedEmbClose(emb);
}

_cf_pdf_out_t *__wrap__cfPDFOutNew(void) {
  _cf_pdf_out_t *pdf = __real__cfPDFOutNew();

  if (cf_v2_texttopdf_active) {
    cf_v2_texttopdf_pdf = pdf;
  }
  return pdf;
}

void __wrap__cfPDFOutFree(_cf_pdf_out_t *pdf) {
  if (cf_v2_texttopdf_pdf == pdf) {
    cf_v2_texttopdf_pdf = NULL;
  }
  __real__cfPDFOutFree(pdf);
}

void __wrap_free(void *pointer) {
  cf_v2_texttopdf_forget_strdup(pointer);
  if (pointer && pointer == cf_v2_texttopdf_pdf) {
    _cf_pdf_out_t *pdf = (_cf_pdf_out_t *)pointer;

    if (pdf->kv && pdf->kvsize >= 0 && pdf->kvsize <= pdf->kvalloc &&
        pdf->kvalloc <= 1024) {
      for (int index = 0; index < pdf->kvsize; index++) {
        cf_v2_texttopdf_forget_strdup(pdf->kv[index].key);
        cf_v2_texttopdf_forget_strdup(pdf->kv[index].value);
        __real_free(pdf->kv[index].key);
        __real_free(pdf->kv[index].value);
      }
    }
    __real_free(pdf->kv);
    __real_free(pdf->pages);
    __real_free(pdf->xref);
    cf_v2_texttopdf_pdf = NULL;
  }
  __real_free(pointer);
}

static void cf_v2_release_texttopdf_lifecycle(void) {
  cf_v2_texttopdf_active = 0;
  while (cf_v2_texttopdf_font_count) {
    __real__cfFontEmbedEmbClose(
        cf_v2_texttopdf_fonts[--cf_v2_texttopdf_font_count]);
  }
  while (cf_v2_texttopdf_strdup_count) {
    __real_free(
        cf_v2_texttopdf_strdups[--cf_v2_texttopdf_strdup_count]);
  }
  memset(cf_v2_texttopdf_fonts, 0, sizeof(cf_v2_texttopdf_fonts));
  memset(cf_v2_texttopdf_strdups, 0, sizeof(cf_v2_texttopdf_strdups));
}
#endif

#ifdef CF_V2_IMAGE_CACHE_CONTINUATION
#include <cupsfilters/image-private.h>

extern void __real_cfImageClose(cf_image_t *image);

static void cf_v2_rebuild_image_cache_list(cf_image_t *image) {
  cf_ic_t *first = NULL;
  cf_ic_t *last = NULL;
  size_t columns;
  size_t rows;

  if (!image || !image->tiles) {
    return;
  }
  columns = image->xsize / CF_TILE_SIZE +
            (image->xsize % CF_TILE_SIZE != 0U);
  rows = image->ysize / CF_TILE_SIZE +
         (image->ysize % CF_TILE_SIZE != 0U);
  if (!columns || !rows || columns > 65536U || rows > 65536U ||
      columns > 1048576U / rows) {
    return;
  }

  for (size_t y = 0; y < rows; y++) {
    for (size_t x = 0; x < columns; x++) {
      cf_ic_t *entry = image->tiles[y][x].ic;
      cf_ic_t *known = first;

      while (known && known != entry) {
        known = known->next;
      }
      if (!entry || known) {
        continue;
      }
      entry->prev = last;
      entry->next = NULL;
      if (last) {
        last->next = entry;
      } else {
        first = entry;
      }
      last = entry;
    }
  }
  image->first = first;
  image->last = last;
}

void __wrap_cfImageClose(cf_image_t *image) {
  /* Recover cache entries detached by the upstream LRU move operation. */
  cf_v2_rebuild_image_cache_list(image);
  __real_cfImageClose(image);
}
#endif

#ifdef CF_V2_STDIO_STREAM_CONTINUATION
#define CF_V2_FDOPEN_STREAMS_MAX 8U

static FILE *cf_v2_fdopen_streams[CF_V2_FDOPEN_STREAMS_MAX];
static size_t cf_v2_fdopen_stream_count;

extern FILE *__real_fdopen(int fd, const char *mode);
extern int __real_fclose(FILE *stream);

static void cf_v2_forget_fdopen_stream(FILE *stream) {
  for (size_t index = 0; index < cf_v2_fdopen_stream_count; index++) {
    if (cf_v2_fdopen_streams[index] != stream) {
      continue;
    }
    cf_v2_fdopen_streams[index] =
        cf_v2_fdopen_streams[--cf_v2_fdopen_stream_count];
    cf_v2_fdopen_streams[cf_v2_fdopen_stream_count] = NULL;
    return;
  }
}

FILE *__wrap_fdopen(int fd, const char *mode) {
  FILE *stream = __real_fdopen(fd, mode);

  if (stream && cf_v2_fdopen_stream_count < CF_V2_FDOPEN_STREAMS_MAX) {
    cf_v2_fdopen_streams[cf_v2_fdopen_stream_count++] = stream;
  }
  return stream;
}

int __wrap_fclose(FILE *stream) {
  cf_v2_forget_fdopen_stream(stream);
  return __real_fclose(stream);
}

static void cf_v2_release_fdopen_streams(void) {
  while (cf_v2_fdopen_stream_count) {
    FILE *stream = cf_v2_fdopen_streams[--cf_v2_fdopen_stream_count];

    cf_v2_fdopen_streams[cf_v2_fdopen_stream_count] = NULL;
    (void)__real_fclose(stream);
  }
}
#endif

#ifdef CF_V2_JOIN_OPTIONS_CONTINUATION
#define CF_V2_JOINED_OPTIONS_MAX 32U

typedef struct cf_v2_joined_options_s {
  cups_option_t *options;
  int count;
} cf_v2_joined_options_t;

static cf_v2_joined_options_t
    cf_v2_joined_options[CF_V2_JOINED_OPTIONS_MAX];
static size_t cf_v2_joined_options_count;

extern int __real_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data,
                                            int num_options,
                                            cups_option_t **options);
extern void __real_cupsFreeOptions(int num_options, cups_option_t *options);

static void cf_v2_forget_joined_options(cups_option_t *options) {
  for (size_t index = 0; index < cf_v2_joined_options_count; index++) {
    if (cf_v2_joined_options[index].options != options) {
      continue;
    }
    cf_v2_joined_options_count--;
    cf_v2_joined_options[index] =
        cf_v2_joined_options[cf_v2_joined_options_count];
    memset(&cf_v2_joined_options[cf_v2_joined_options_count], 0,
           sizeof(cf_v2_joined_options[0]));
    return;
  }
}

int __wrap_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data, int num_options,
                                    cups_option_t **options) {
  cups_option_t *initial = options ? *options : NULL;
  int result = __real_cfJoinJobOptionsAndAttrs(data, num_options, options);

  if (options && *options && *options != initial &&
      cf_v2_joined_options_count < CF_V2_JOINED_OPTIONS_MAX) {
    cf_v2_joined_options[cf_v2_joined_options_count++] =
        (cf_v2_joined_options_t){*options, result};
  }
  return result;
}

void __wrap_cupsFreeOptions(int num_options, cups_option_t *options) {
  cf_v2_forget_joined_options(options);
  __real_cupsFreeOptions(num_options, options);
}

static void cf_v2_release_joined_options(void) {
  while (cf_v2_joined_options_count) {
    cf_v2_joined_options_t *owner =
        &cf_v2_joined_options[--cf_v2_joined_options_count];
    __real_cupsFreeOptions(owner->count, owner->options);
    memset(owner, 0, sizeof(*owner));
  }
}
#endif

#ifdef CF_V2_FILTER_OPTIONS_CONTINUATION
#include <cupsfilters/ipp-options-private.h>

#define CF_V2_FILTER_OPTIONS_MAX 8U

static cf_filter_options_t *
    cf_v2_filter_options[CF_V2_FILTER_OPTIONS_MAX];
static size_t cf_v2_filter_options_count;

extern cf_filter_options_t *__real_cfFilterOptionsCreate(
    size_t num_options, cups_option_t *options);
extern void __real_cfFilterOptionsDelete(cf_filter_options_t *options);

static void cf_v2_forget_filter_options(cf_filter_options_t *options) {
  for (size_t index = 0; index < cf_v2_filter_options_count; index++) {
    if (cf_v2_filter_options[index] != options) {
      continue;
    }
    cf_v2_filter_options_count--;
    cf_v2_filter_options[index] =
        cf_v2_filter_options[cf_v2_filter_options_count];
    cf_v2_filter_options[cf_v2_filter_options_count] = NULL;
    return;
  }
}

cf_filter_options_t *__wrap_cfFilterOptionsCreate(size_t num_options,
                                                   cups_option_t *options) {
  cf_filter_options_t *result =
      __real_cfFilterOptionsCreate(num_options, options);
  if (result && cf_v2_filter_options_count < CF_V2_FILTER_OPTIONS_MAX) {
    cf_v2_filter_options[cf_v2_filter_options_count++] = result;
  }
  return result;
}

void __wrap_cfFilterOptionsDelete(cf_filter_options_t *options) {
  cf_v2_forget_filter_options(options);
  __real_cfFilterOptionsDelete(options);
}

static void cf_v2_release_filter_options(void) {
  while (cf_v2_filter_options_count) {
    cf_filter_options_t *options =
        cf_v2_filter_options[--cf_v2_filter_options_count];
    cf_v2_filter_options[cf_v2_filter_options_count] = NULL;
    __real_cfFilterOptionsDelete(options);
  }
}
#endif

#ifndef CF_V2_MAX_DOCUMENT
#define CF_V2_MAX_DOCUMENT (2U * 1024U * 1024U)
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  const uint8_t *document;
  size_t document_size;

  if (!cf_v2_split_input(data, size, CF_V2_MAX_DOCUMENT, &document,
                         &document_size, &control)) {
    return 0;
  }
#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
  cf_v2_texttopdf_active = 1;
#endif
  (void)cf_v2_execute_direct(document, document_size, &control, 0, &result);
#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
  cf_v2_release_texttopdf_lifecycle();
#endif
  cf_v2_free_run_result(&result);
#ifdef CF_V2_JOIN_OPTIONS_CONTINUATION
  cf_v2_release_joined_options();
#endif
#ifdef CF_V2_FILTER_OPTIONS_CONTINUATION
  cf_v2_release_filter_options();
#endif
  return 0;
}
