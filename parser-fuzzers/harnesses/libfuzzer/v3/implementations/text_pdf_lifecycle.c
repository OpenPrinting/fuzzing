// SPDX-License-Identifier: Apache-2.0
#include "text_pdf_lifecycle.h"

#include <cupsfilters/pdfutils-private.h>
#include <fontconfig/fontconfig.h>
#include <sanitizer/lsan_interface.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_TEXT_PDF_TRACKED 4096U

static int cf_v3_text_pdf_active;
static _cf_pdf_out_t *cf_v3_text_pdf_output;
static _cf_fontembed_emb_params_t *
    cf_v3_text_pdf_fonts[CF_V3_TEXT_PDF_TRACKED];
static size_t cf_v3_text_pdf_font_count;
static char *cf_v3_text_pdf_strdups[CF_V3_TEXT_PDF_TRACKED];
static size_t cf_v3_text_pdf_strdup_count;

extern _cf_pdf_out_t *__real__cfPDFOutNew(void);
extern void __real__cfPDFOutFree(_cf_pdf_out_t *pdf);
extern _cf_fontembed_emb_params_t *__real__cfFontEmbedEmbNew(
    _cf_fontembed_fontfile_t *font, _cf_fontembed_emb_dest_t destination,
    _cf_fontembed_emb_constraint_t mode);
extern void __real__cfFontEmbedEmbClose(_cf_fontembed_emb_params_t *embed);
extern FcBool __real_FcInit(void);
extern char *__real_strdup(const char *value);
extern void __real_free(void *pointer);

static void
cf_v3_text_pdf_forget_strdup(void *pointer)
{
  for (size_t index = 0U; index < cf_v3_text_pdf_strdup_count; index++)
  {
    if (cf_v3_text_pdf_strdups[index] != pointer)
      continue;
    cf_v3_text_pdf_strdups[index] =
        cf_v3_text_pdf_strdups[--cf_v3_text_pdf_strdup_count];
    cf_v3_text_pdf_strdups[cf_v3_text_pdf_strdup_count] = NULL;
    return;
  }
}

FcBool
__wrap_FcInit(void)
{
  FcBool result;

  __lsan_disable();
  result = __real_FcInit();
  __lsan_enable();
  return result;
}

char *
__wrap_strdup(const char *value)
{
  char *copy = __real_strdup(value);

  if (cf_v3_text_pdf_active && cf_v3_text_pdf_output && copy &&
      cf_v3_text_pdf_strdup_count < CF_V3_TEXT_PDF_TRACKED)
    cf_v3_text_pdf_strdups[cf_v3_text_pdf_strdup_count++] = copy;
  return copy;
}

_cf_fontembed_emb_params_t *
__wrap__cfFontEmbedEmbNew(
    _cf_fontembed_fontfile_t *font, _cf_fontembed_emb_dest_t destination,
    _cf_fontembed_emb_constraint_t mode)
{
  _cf_fontembed_emb_params_t *embed =
      __real__cfFontEmbedEmbNew(font, destination, mode);

  if (cf_v3_text_pdf_active && embed &&
      cf_v3_text_pdf_font_count < CF_V3_TEXT_PDF_TRACKED)
    cf_v3_text_pdf_fonts[cf_v3_text_pdf_font_count++] = embed;
  return embed;
}

void
__wrap__cfFontEmbedEmbClose(_cf_fontembed_emb_params_t *embed)
{
  for (size_t index = 0U; index < cf_v3_text_pdf_font_count; index++)
  {
    if (cf_v3_text_pdf_fonts[index] != embed)
      continue;
    cf_v3_text_pdf_fonts[index] =
        cf_v3_text_pdf_fonts[--cf_v3_text_pdf_font_count];
    cf_v3_text_pdf_fonts[cf_v3_text_pdf_font_count] = NULL;
    break;
  }
  __real__cfFontEmbedEmbClose(embed);
}

_cf_pdf_out_t *
__wrap__cfPDFOutNew(void)
{
  _cf_pdf_out_t *output = __real__cfPDFOutNew();

  if (cf_v3_text_pdf_active)
    cf_v3_text_pdf_output = output;
  return output;
}

void
__wrap__cfPDFOutFree(_cf_pdf_out_t *output)
{
  if (cf_v3_text_pdf_output == output)
    cf_v3_text_pdf_output = NULL;
  __real__cfPDFOutFree(output);
}

void
__wrap_free(void *pointer)
{
  cf_v3_text_pdf_forget_strdup(pointer);
  if (pointer && pointer == cf_v3_text_pdf_output)
  {
    _cf_pdf_out_t *output = (_cf_pdf_out_t *)pointer;

    if (output->kv && output->kvsize >= 0 &&
        output->kvsize <= output->kvalloc && output->kvalloc <= 1024)
      for (int index = 0; index < output->kvsize; index++)
      {
        cf_v3_text_pdf_forget_strdup(output->kv[index].key);
        cf_v3_text_pdf_forget_strdup(output->kv[index].value);
        __real_free(output->kv[index].key);
        __real_free(output->kv[index].value);
      }
    __real_free(output->kv);
    __real_free(output->pages);
    __real_free(output->xref);
    cf_v3_text_pdf_output = NULL;
  }
  __real_free(pointer);
}

void
cf_v3_text_pdf_lifecycle_end(void)
{
  cf_v3_text_pdf_active = 0;
  while (cf_v3_text_pdf_font_count)
    __real__cfFontEmbedEmbClose(
        cf_v3_text_pdf_fonts[--cf_v3_text_pdf_font_count]);
  while (cf_v3_text_pdf_strdup_count)
    __real_free(cf_v3_text_pdf_strdups[--cf_v3_text_pdf_strdup_count]);
  memset(cf_v3_text_pdf_fonts, 0, sizeof(cf_v3_text_pdf_fonts));
  memset(cf_v3_text_pdf_strdups, 0, sizeof(cf_v3_text_pdf_strdups));
  cf_v3_text_pdf_output = NULL;
}

void
cf_v3_text_pdf_lifecycle_begin(void)
{
  if (cf_v3_text_pdf_font_count || cf_v3_text_pdf_strdup_count ||
      cf_v3_text_pdf_output)
    cf_v3_text_pdf_lifecycle_end();
  cf_v3_text_pdf_active = 1;
}
