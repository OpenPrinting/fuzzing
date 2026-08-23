// SPDX-License-Identifier: Apache-2.0
#include "pdf_filter_lifecycle.h"

#include <cups/cups.h>
#include <cups/language.h>
#include <cups/pwg.h>
#include <cupsfilters/ipp-options-private.h>
#include <ppd/ppd.h>

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_PDF_FILTER_OPTIONS_MAX 32U
#define CF_V3_PDF_FILTER_STREAMS_MAX 16U
#define CF_V3_PDF_FILTER_ALLOCATION_CAPACITY (1U << 18)

static int cf_v3_pdf_filter_active;
static int cf_v3_pdf_filter_track_allocations;
static cf_filter_options_t *
    cf_v3_pdf_filter_options[CF_V3_PDF_FILTER_OPTIONS_MAX];
static size_t cf_v3_pdf_filter_option_count;
static FILE *cf_v3_pdf_filter_streams[CF_V3_PDF_FILTER_STREAMS_MAX];
static size_t cf_v3_pdf_filter_stream_count;
static void *
    cf_v3_pdf_filter_allocations[CF_V3_PDF_FILTER_ALLOCATION_CAPACITY];
static void *const cf_v3_pdf_filter_tombstone = (void *)(uintptr_t)1U;

extern cf_filter_options_t *__real_cfFilterOptionsCreate(
    size_t num_options, cups_option_t *options);
extern void __real_cfFilterOptionsDelete(cf_filter_options_t *options);
extern FILE *__real_fdopen(int descriptor, const char *mode);
extern int __real_fclose(FILE *stream);
extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t count, size_t size);
extern void *__real_realloc(void *pointer, size_t size);
extern char *__real_strdup(const char *value);
extern void __real_free(void *pointer);
extern int __real_fputs(const char *text, FILE *stream);

static size_t
cf_v3_pdf_filter_pointer_hash(const void *pointer)
{
  uintptr_t value = (uintptr_t)pointer >> 4U;

  value ^= value >> 17U;
  value ^= value >> 9U;
  return (size_t)(value & (CF_V3_PDF_FILTER_ALLOCATION_CAPACITY - 1U));
}

static void
cf_v3_pdf_filter_track(void *pointer)
{
  size_t index;
  size_t available = SIZE_MAX;

  if (!cf_v3_pdf_filter_active || !cf_v3_pdf_filter_track_allocations ||
      !pointer)
    return;
  index = cf_v3_pdf_filter_pointer_hash(pointer);
  for (size_t probe = 0U;
       probe < CF_V3_PDF_FILTER_ALLOCATION_CAPACITY; probe++)
  {
    void *entry = cf_v3_pdf_filter_allocations[index];

    if (entry == pointer)
      return;
    if (entry == cf_v3_pdf_filter_tombstone && available == SIZE_MAX)
      available = index;
    else if (!entry)
    {
      cf_v3_pdf_filter_allocations[
          available == SIZE_MAX ? index : available] = pointer;
      return;
    }
    index = (index + 1U) &
            (CF_V3_PDF_FILTER_ALLOCATION_CAPACITY - 1U);
  }
}

static void
cf_v3_pdf_filter_forget_allocation(void *pointer)
{
  size_t index;

  if (!pointer)
    return;
  index = cf_v3_pdf_filter_pointer_hash(pointer);
  for (size_t probe = 0U;
       probe < CF_V3_PDF_FILTER_ALLOCATION_CAPACITY; probe++)
  {
    void *entry = cf_v3_pdf_filter_allocations[index];

    if (!entry)
      return;
    if (entry == pointer)
    {
      cf_v3_pdf_filter_allocations[index] = cf_v3_pdf_filter_tombstone;
      return;
    }
    index = (index + 1U) &
            (CF_V3_PDF_FILTER_ALLOCATION_CAPACITY - 1U);
  }
}

void *
cf_v3_pdf_filter_malloc(size_t size)
{
  void *pointer = __real_malloc(size);

  cf_v3_pdf_filter_track(pointer);
  return pointer;
}

void
cf_v3_pdf_filter_free(void *pointer)
{
  cf_v3_pdf_filter_forget_allocation(pointer);
  __real_free(pointer);
}

/* Keep linker aliases required by private graph oracles without assigning
 * ownership of dependency/runtime allocations to the filter lifecycle. */
void *
__wrap_malloc(size_t size)
{
  return __real_malloc(size);
}

void *
__wrap_calloc(size_t count, size_t size)
{
  return __real_calloc(count, size);
}

void *
__wrap_realloc(void *pointer, size_t size)
{
  return __real_realloc(pointer, size);
}

char *
__wrap_strdup(const char *value)
{
  return __real_strdup(value);
}

void
__wrap_free(void *pointer)
{
  cf_v3_pdf_filter_forget_allocation(pointer);
  __real_free(pointer);
}

int
__wrap_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;
  int result;

  if (stream == stderr && format && !strncmp(format, "DEBUG:", 6U))
    return 0;
  va_start(arguments, format);
  result = vfprintf(stream, format, arguments);
  va_end(arguments);
  return result;
}

int
__wrap_fputs(const char *text, FILE *stream)
{
  if (stream == stderr && text && !strncmp(text, "DEBUG:", 6U))
    return 0;
  return __real_fputs(text, stream);
}

static void
cf_v3_pdf_filter_forget_option(cf_filter_options_t *options)
{
  for (size_t index = 0U; index < cf_v3_pdf_filter_option_count; index++)
  {
    if (cf_v3_pdf_filter_options[index] != options)
      continue;
    cf_v3_pdf_filter_options[index] =
        cf_v3_pdf_filter_options[--cf_v3_pdf_filter_option_count];
    cf_v3_pdf_filter_options[cf_v3_pdf_filter_option_count] = NULL;
    return;
  }
}

static void
cf_v3_pdf_filter_forget_stream(FILE *stream)
{
  for (size_t index = 0U; index < cf_v3_pdf_filter_stream_count; index++)
  {
    if (cf_v3_pdf_filter_streams[index] != stream)
      continue;
    cf_v3_pdf_filter_streams[index] =
        cf_v3_pdf_filter_streams[--cf_v3_pdf_filter_stream_count];
    cf_v3_pdf_filter_streams[cf_v3_pdf_filter_stream_count] = NULL;
    return;
  }
}

cf_filter_options_t *
__wrap_cfFilterOptionsCreate(size_t num_options, cups_option_t *options)
{
  cf_filter_options_t *created =
      __real_cfFilterOptionsCreate(num_options, options);

  if (cf_v3_pdf_filter_active && created &&
      cf_v3_pdf_filter_option_count < CF_V3_PDF_FILTER_OPTIONS_MAX)
    cf_v3_pdf_filter_options[cf_v3_pdf_filter_option_count++] = created;
  return created;
}

void
__wrap_cfFilterOptionsDelete(cf_filter_options_t *options)
{
  cf_v3_pdf_filter_forget_option(options);
  __real_cfFilterOptionsDelete(options);
}

FILE *
__wrap_fdopen(int descriptor, const char *mode)
{
  FILE *stream = __real_fdopen(descriptor, mode);

  if (cf_v3_pdf_filter_active && stream &&
      cf_v3_pdf_filter_stream_count < CF_V3_PDF_FILTER_STREAMS_MAX)
    cf_v3_pdf_filter_streams[cf_v3_pdf_filter_stream_count++] = stream;
  return stream;
}

int
__wrap_fclose(FILE *stream)
{
  cf_v3_pdf_filter_forget_stream(stream);
  return __real_fclose(stream);
}

void
cf_v3_pdf_filter_lifecycle_end(void)
{
  cf_v3_pdf_filter_active = 0;
  while (cf_v3_pdf_filter_stream_count)
    (void)__real_fclose(
        cf_v3_pdf_filter_streams[--cf_v3_pdf_filter_stream_count]);
  while (cf_v3_pdf_filter_option_count)
    __real_cfFilterOptionsDelete(
        cf_v3_pdf_filter_options[--cf_v3_pdf_filter_option_count]);
  cf_v3_pdf_filter_track_allocations = 0;
  for (size_t index = 0U;
       index < CF_V3_PDF_FILTER_ALLOCATION_CAPACITY; index++)
  {
    void *pointer = cf_v3_pdf_filter_allocations[index];

    if (pointer && pointer != cf_v3_pdf_filter_tombstone)
      __real_free(pointer);
    cf_v3_pdf_filter_allocations[index] = NULL;
  }
  memset(cf_v3_pdf_filter_streams, 0, sizeof(cf_v3_pdf_filter_streams));
  memset(cf_v3_pdf_filter_options, 0, sizeof(cf_v3_pdf_filter_options));
}

void
cf_v3_pdf_filter_lifecycle_begin(int faithful)
{
  if (cf_v3_pdf_filter_stream_count || cf_v3_pdf_filter_option_count)
    cf_v3_pdf_filter_lifecycle_end();
  {
    static int warmed;

    if (!warmed)
    {
      cups_option_t *options = NULL;
      int count = cupsParseOptions(
          "number-up=1 print-scaling=none", NULL, 0, &options);

      cupsFreeOptions(count, options);
      (void)pwgMediaForPWG("iso_a4_210x297mm");
      (void)cupsLangGet(NULL);
      (void)ppdGlobals();
      warmed = 1;
    }
  }
  cf_v3_pdf_filter_track_allocations = !faithful;
  cf_v3_pdf_filter_active = 1;
}
