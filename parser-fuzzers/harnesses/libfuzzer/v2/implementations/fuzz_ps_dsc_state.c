// SPDX-License-Identifier: Apache-2.0
#include "../include/direct_route.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_PS_DSC_MAGIC "PSDSC001"
#define CF_V2_PS_DSC_MAGIC_SIZE 8U
#define CF_V2_PS_DSC_SELECTORS 16U
#define CF_V2_PS_DSC_MAX_PAYLOAD 1024U
#define CF_V2_PS_APPEND_LITERAL(buffer, literal) \
  cf_v2_ps_append((buffer), (literal), sizeof(literal) - 1U)

typedef struct cf_v2_ps_buffer_s
{
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v2_ps_buffer_t;

static int
cf_v2_ps_append(cf_v2_ps_buffer_t *buffer, const void *data, size_t size)
{
  if (!buffer || !data || size > buffer->capacity - buffer->size)
    return 0;
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int
cf_v2_ps_printf(cf_v2_ps_buffer_t *buffer, const char *format, ...)
{
  va_list arguments;
  int length;

  if (!buffer || buffer->size >= buffer->capacity)
    return 0;
  va_start(arguments, format);
  length = vsnprintf((char *)buffer->data + buffer->size,
                     buffer->capacity - buffer->size, format, arguments);
  va_end(arguments);
  if (length < 0 || (size_t)length >= buffer->capacity - buffer->size)
    return 0;
  buffer->size += (size_t)length;
  return 1;
}

static void
cf_v2_ps_dsc_control(const uint8_t selector[CF_V2_PS_DSC_SELECTORS],
                     cf_v2_control_t *control)
{
  control->page_size = selector[0];
  control->number_up = selector[1];
  control->position = selector[2];
  control->quality = selector[3];
  control->media_type = selector[4];
  control->output_order = selector[5];
  control->copies = selector[6];
  control->reserved = selector[7];
  control->sides = selector[8];
  control->orientation = selector[9];
  control->scaling = selector[10];
  control->mirror = selector[11];
  control->route_mode = selector[12];
  control->ppd_profile = selector[13];
  control->color_model = selector[14];
  control->resolution = selector[15];
}

static uint8_t
cf_v2_ps_material(const uint8_t *payload, size_t payload_size,
                  unsigned page, size_t offset)
{
  return (uint8_t)(payload[(offset + page * 17U) % payload_size] ^
                   (uint8_t)(page * 29U + offset * 13U));
}

static int
cf_v2_ps_append_hex(cf_v2_ps_buffer_t *buffer, const uint8_t *payload,
                    size_t payload_size, unsigned page, size_t length)
{
  static const char digits[] = "0123456789abcdef";
  size_t offset;

  if (!cf_v2_ps_append(buffer, "<", 1U))
    return 0;
  for (offset = 0; offset < length; offset ++)
  {
    uint8_t value = cf_v2_ps_material(payload, payload_size, page, offset);
    char pair[2] = {digits[value >> 4U], digits[value & 15U]};

    if (!cf_v2_ps_append(buffer, pair, sizeof(pair)))
      return 0;
  }
  return CF_V2_PS_APPEND_LITERAL(buffer, "> pop\n");
}

static int
cf_v2_ps_append_binary(cf_v2_ps_buffer_t *buffer,
                       const uint8_t *payload, size_t payload_size,
                       unsigned page, unsigned mode, size_t length)
{
  size_t offset;

  if (mode == 1U)
  {
    if (!cf_v2_ps_printf(buffer, "%%%%BeginBinary: %zu\n", length))
      return 0;
  }
  else if (mode == 2U)
  {
    if (!cf_v2_ps_printf(buffer, "%%%%BeginData: %zu Binary Bytes\n", length))
      return 0;
  }
  else
  {
    if (!cf_v2_ps_printf(buffer, "%%%%BeginData: %zu ASCII Bytes\n", length))
      return 0;
  }

  for (offset = 0; offset < length; offset ++)
  {
    uint8_t value = cf_v2_ps_material(payload, payload_size, page, offset + 31U);

    if (mode == 3U)
      value = (uint8_t)('!' + value % 94U);
    if (!cf_v2_ps_append(buffer, &value, 1U))
      return 0;
  }
  return cf_v2_ps_printf(buffer, "\n%%%%End%s\n",
                         mode == 1U ? "Binary" : "Data");
}

static uint8_t *
cf_v2_build_ps_dsc_document(const cf_v2_ps_dsc_state_t *state,
                            const uint8_t *payload, size_t payload_size,
                            size_t *document_size)
{
  const size_t capacity = 32768U + (size_t)state->page_count *
                          (payload_size * 3U + 4096U);
  const unsigned section_mode = state->section_mode;
  const size_t material_length = payload_size < 64U ? payload_size : 64U;
  cf_v2_ps_buffer_t buffer;
  unsigned page;

  buffer.data = (uint8_t *)malloc(capacity);
  buffer.size = 0;
  buffer.capacity = capacity;
  if (!buffer.data)
    return NULL;

  if (!cf_v2_ps_printf(&buffer,
                       "%%!PS-Adobe-3.0\n"
                       "%%%%Creator: cups-filters-v2-dsc-state\n"
                       "%%%%Title: (bounded DSC state %u)\n"
                       "%%%%For: (oss-fuzz)\n",
                       section_mode))
    goto fail;
  if (state->trailer_mode == 1U)
  {
    if (!CF_V2_PS_APPEND_LITERAL(
            &buffer, "%%Pages: (atend)\n%%BoundingBox: (atend)\n"))
      goto fail;
  }
  else if (!cf_v2_ps_printf(&buffer,
                            "%%%%Pages: %u\n%%%%BoundingBox: 0 0 595 842\n",
                            state->page_count))
    goto fail;
  if (!cf_v2_ps_printf(&buffer, "%%%%DocumentData: %s\n%%%%EndComments\n",
                       state->binary_mode ? "Binary" : "Clean7Bit"))
    goto fail;

  if (section_mode & 1U)
  {
    if (!CF_V2_PS_APPEND_LITERAL(
            &buffer,
            "%%BeginProlog\n"
            "/v2mark { newpath 0 0 moveto 8 0 lineto 8 8 lineto "
            "closepath stroke } bind def\n"
            "%%EndProlog\n"))
      goto fail;
  }
  if (section_mode & 2U)
  {
    if (!CF_V2_PS_APPEND_LITERAL(&buffer, "%%BeginSetup\n") ||
        ((section_mode & 8U) &&
         !CF_V2_PS_APPEND_LITERAL(
             &buffer, "%%IncludeFeature: *PageSize A4\n")) ||
        !CF_V2_PS_APPEND_LITERAL(&buffer, "%%EndSetup\n"))
      goto fail;
  }

  for (page = 1U; page <= state->page_count; page ++)
  {
    const size_t binary_length =
        1U + (cf_v2_ps_material(payload, payload_size, page, 7U) %
              material_length);

    if (!cf_v2_ps_printf(&buffer,
                         "%%%%Page: (%u-v2) %u\n"
                         "%%%%PageBoundingBox: %u %u %u %u\n",
                         page, page, page % 11U, page % 13U,
                         580U - page % 7U, 827U - page % 5U))
      goto fail;
    if (section_mode & 4U)
    {
      if (!CF_V2_PS_APPEND_LITERAL(&buffer, "%%BeginPageSetup\n") ||
          ((section_mode & 8U) &&
           !CF_V2_PS_APPEND_LITERAL(
               &buffer, "%%IncludeFeature: *Resolution 300dpi\n")) ||
          !CF_V2_PS_APPEND_LITERAL(&buffer, "%%EndPageSetup\n"))
        goto fail;
    }
    if (!cf_v2_ps_printf(&buffer, "gsave %u %u translate\n",
                         8U + page, 12U + page) ||
        !cf_v2_ps_append_hex(&buffer, payload, payload_size, page,
                             material_length))
      goto fail;

    if (state->binary_mode &&
        !cf_v2_ps_append_binary(&buffer, payload, payload_size, page,
                                state->binary_mode, binary_length))
      goto fail;

    if (section_mode & 16U)
    {
      if (!cf_v2_ps_printf(&buffer,
                           "%%%%BeginDocument: nested-%u.ps\n"
                           "%%!PS-Adobe-3.0\n"
                           "%%%%Page: nested %u\n"
                           "0 0 moveto\n"
                           "%%%%Trailer\n"
                           "%%%%EOF\n"
                           "%%%%EndDocument\n",
                           page, page))
        goto fail;
    }
    if (!CF_V2_PS_APPEND_LITERAL(&buffer, "grestore showpage\n"))
      goto fail;
  }

  if (state->trailer_mode != 2U)
  {
    if (!cf_v2_ps_printf(&buffer,
                         "%%%%Trailer\n"
                         "%%%%Pages: %u\n"
                         "%%%%BoundingBox: 0 0 595 842\n",
                         state->page_count))
      goto fail;
    if (state->trailer_mode == 3U &&
        !CF_V2_PS_APPEND_LITERAL(
            &buffer, "%%DocumentSuppliedResources: procset v2\n"))
      goto fail;
  }
  if (!CF_V2_PS_APPEND_LITERAL(&buffer, "%%EOF\n"))
    goto fail;

  *document_size = buffer.size;
  return buffer.data;

fail:
  free(buffer.data);
  return NULL;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size = CF_V2_PS_DSC_MAGIC_SIZE + CF_V2_PS_DSC_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  cf_v2_control_t control;
  cf_v2_ps_dsc_state_t state;
  cf_v2_run_result_t result;
  uint8_t *document;
  size_t document_size = 0;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_PS_DSC_MAX_PAYLOAD ||
      memcmp(data, CF_V2_PS_DSC_MAGIC, CF_V2_PS_DSC_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_PS_DSC_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  cf_v2_ps_dsc_control(selector, &control);
  cf_v2_decode_ps_dsc_state(&control, &state);
  document = cf_v2_build_ps_dsc_document(&state, payload, payload_size,
                                         &document_size);
  if (!document)
    return 0;

  (void)cf_v2_execute_direct(document, document_size, &control, 0, &result);
  cf_v2_free_run_result(&result);
  free(document);
  return 0;
}
