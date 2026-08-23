// SPDX-License-Identifier: Apache-2.0
#include "pwg_filter_adapter.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_PWG_TRACKED_MAX 4096U

#ifndef CF_V3_PWG_TO_PDF_SOURCE
#error "CF_V3_PWG_TO_PDF_SOURCE must name pwgtopdf.c"
#endif

static void *cf_v3_pwg_tracked[CF_V3_PWG_TRACKED_MAX];
static size_t cf_v3_pwg_tracked_count;
static int cf_v3_pwg_tracker_overflow;

static size_t
cf_v3_pwg_find(void *pointer)
{
  size_t index;

  for (index = 0U; index < cf_v3_pwg_tracked_count; index ++)
    if (cf_v3_pwg_tracked[index] == pointer)
      return index;
  return SIZE_MAX;
}

static void
cf_v3_pwg_track(void *pointer)
{
  if (!pointer || cf_v3_pwg_find(pointer) != SIZE_MAX)
    return;
  if (cf_v3_pwg_tracked_count >= CF_V3_PWG_TRACKED_MAX)
  {
    cf_v3_pwg_tracker_overflow = 1;
    return;
  }
  cf_v3_pwg_tracked[cf_v3_pwg_tracked_count ++] = pointer;
}

static void
cf_v3_pwg_forget(void *pointer)
{
  size_t index = cf_v3_pwg_find(pointer);

  if (index == SIZE_MAX)
    return;
  cf_v3_pwg_tracked[index] =
      cf_v3_pwg_tracked[-- cf_v3_pwg_tracked_count];
  cf_v3_pwg_tracked[cf_v3_pwg_tracked_count] = NULL;
}

static void *
cf_v3_pwg_malloc(size_t size)
{
  void *pointer = malloc(size);

  cf_v3_pwg_track(pointer);
  return pointer;
}

static void *
cf_v3_pwg_calloc(size_t count, size_t size)
{
  void *pointer = calloc(count, size);

  cf_v3_pwg_track(pointer);
  return pointer;
}

static void *
cf_v3_pwg_realloc(void *pointer, size_t size)
{
  size_t index = cf_v3_pwg_find(pointer);
  void *replacement = realloc(pointer, size);

  if (!replacement)
  {
    if (!size)
      cf_v3_pwg_forget(pointer);
    return NULL;
  }
  if (index == SIZE_MAX)
    cf_v3_pwg_track(replacement);
  else
    cf_v3_pwg_tracked[index] = replacement;
  return replacement;
}

static char *
cf_v3_pwg_strdup(const char *value)
{
  size_t length = strlen(value) + 1U;
  char *copy = (char *)malloc(length);

  if (copy)
  {
    memcpy(copy, value, length);
    cf_v3_pwg_track(copy);
  }
  return copy;
}

static void
cf_v3_pwg_free(void *pointer)
{
  cf_v3_pwg_forget(pointer);
  free(pointer);
}

void
cf_v3_pwg_filter_release(void)
{
  while (cf_v3_pwg_tracked_count)
  {
    free(cf_v3_pwg_tracked[-- cf_v3_pwg_tracked_count]);
    cf_v3_pwg_tracked[cf_v3_pwg_tracked_count] = NULL;
  }
}

int
cf_v3_pwg_filter_tracker_overflowed(void)
{
  int overflow = cf_v3_pwg_tracker_overflow;

  cf_v3_pwg_tracker_overflow = 0;
  return overflow;
}

/* Keep the production algorithm intact while giving its otherwise unfreed
 * per-job allocations a process-lifetime continuation suitable for libFuzzer. */
#define init_pdf_info cf_v3_pwg_init_pdf_info
#define free_pdf_info cf_v3_pwg_free_pdf_info
#define split_strings cf_v3_pwg_split_strings
#define int_to_fwstring cf_v3_pwg_int_to_fwstring
#define cfFilterPWGToPDF cf_v3_pwg_filter
#define malloc cf_v3_pwg_malloc
#define calloc cf_v3_pwg_calloc
#define realloc cf_v3_pwg_realloc
#define strdup cf_v3_pwg_strdup
#define free cf_v3_pwg_free
#include CF_V3_PWG_TO_PDF_SOURCE
#undef free
#undef strdup
#undef realloc
#undef calloc
#undef malloc
#undef cfFilterPWGToPDF
#undef int_to_fwstring
#undef split_strings
#undef free_pdf_info
#undef init_pdf_info

int
cf_v3_pwg_post_ppd_load(cf_filter_data_t *data)
{
  static const char name[] = "pclm-strip-height-preferred";
  ipp_attribute_t *attribute;
  char value[64];
  char *end = NULL;
  long preferred;

  if (!data || !data->printer_attrs ||
      !(attribute = ippFindAttribute(data->printer_attrs, name,
                                     IPP_TAG_ZERO)))
    return 0;
  if (ippGetValueTag(attribute) == IPP_TAG_INTEGER)
    return 0;

  value[0] = '\0';
  ippAttributeString(attribute, value, sizeof(value));
  preferred = strtol(value, &end, 10);
  if (!end || end == value || *end || preferred < 0 || preferred > INT_MAX)
    return 0;
  ippDeleteAttribute(data->printer_attrs, attribute);
  if (!ippAddInteger(data->printer_attrs, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     name, (int)preferred))
    return -1;
  return 0;
}
