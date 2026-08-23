// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PPD_RECORD_CONTRACT_H
#define CUPSFILTERS_FUZZ_V3_PPD_RECORD_CONTRACT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline int
cf_v3_ppd_record_space(uint8_t byte)
{
  return byte == ' ' || byte == '\f' || byte == '\n' || byte == '\r' ||
         byte == '\t' || byte == '\v';
}

static inline size_t
cf_v3_ppd_record_keyword(const uint8_t *line, size_t size, char *keyword,
                         size_t capacity)
{
  size_t input_offset = 0U;
  size_t keyword_size = 0U;
  int separator = 0;

  while (input_offset < size && line[input_offset] == 0x1aU)
    input_offset ++;
  if (input_offset >= size || line[input_offset++] != '*')
    return SIZE_MAX;

  while (input_offset < size)
  {
    uint8_t byte = line[input_offset++];

    if (byte == 0x1aU)
      continue;
    if (byte == ':' || cf_v3_ppd_record_space(byte))
    {
      separator = 1;
      break;
    }
    if (byte < '!' || byte > '~' || byte == '/' || keyword_size >= capacity)
      return SIZE_MAX;
    keyword[keyword_size++] = (char)byte;
  }

  return separator ? keyword_size : SIZE_MAX;
}

static inline int
cf_v3_ppd_short_filter_record(const uint8_t *line, size_t size)
{
  char keyword[32];
  size_t keyword_size =
      cf_v3_ppd_record_keyword(line, size, keyword, sizeof(keyword));
  size_t offset;
  size_t value_size = 0U;
  size_t trimmed_size = 0U;
  uint8_t last_non_space = 0U;
  int started = 0;

  if (!((keyword_size == sizeof("cupsFilter") - 1U &&
         memcmp(keyword, "cupsFilter", keyword_size) == 0) ||
        (keyword_size == sizeof("cupsFilter2") - 1U &&
         memcmp(keyword, "cupsFilter2", keyword_size) == 0)))
    return 0;

  for (offset = 0U; offset < size && line[offset] != ':'; offset ++);
  if (offset >= size)
    return 0;

  for (offset ++; offset < size; offset ++)
  {
    uint8_t byte = line[offset];

    if (byte == 0x1aU)
      continue;
    if (byte == '\0' || byte == '\r' || byte == '\n')
      break;
    if (!started && cf_v3_ppd_record_space(byte))
      continue;

    started = 1;
    value_size ++;
    if (!cf_v3_ppd_record_space(byte))
    {
      trimmed_size = value_size;
      last_non_space = byte;
    }
  }

  value_size = trimmed_size;
  if (last_non_space == '"')
    value_size = value_size >= 2U ? value_size - 2U : 0U;
  return value_size < 10U;
}

static inline size_t
cf_v3_ppd_record_line_end(const uint8_t *input, size_t size, size_t offset)
{
  size_t end = offset;

  while (end < size && input[end] != '\r' && input[end] != '\n')
    end ++;
  if (end < size && input[end++] == '\r' && end < size && input[end] == '\n')
    end ++;
  return end;
}

enum
{
  CF_V3_PPD_SINGLETON_LANGUAGE_ENCODING = 1U << 0,
  CF_V3_PPD_SINGLETON_NICKNAME = 1U << 1,
  CF_V3_PPD_SINGLETON_JCL_BEGIN = 1U << 2,
  CF_V3_PPD_SINGLETON_JCL_END = 1U << 3,
  CF_V3_PPD_SINGLETON_JCL_TO_PS = 1U << 4,
  CF_V3_PPD_SINGLETON_JCL_TO_PDF = 1U << 5
};

static inline unsigned int
cf_v3_ppd_owned_singleton_bit(const uint8_t *line, size_t size)
{
  static const char *const keywords[] = {
    "LanguageEncoding",
    "NickName",
    "JCLBegin",
    "JCLEnd",
    "JCLToPSInterpreter",
    "JCLToPDFInterpreter"
  };
  char keyword[32];
  size_t index;
  size_t keyword_size =
      cf_v3_ppd_record_keyword(line, size, keyword, sizeof(keyword));

  if (keyword_size == SIZE_MAX)
    return 0U;

  for (index = 0U; index < sizeof(keywords) / sizeof(keywords[0]); index ++)
  {
    size_t expected_size = strlen(keywords[index]);

    if (keyword_size == expected_size &&
        memcmp(keyword, keywords[index], expected_size) == 0)
      return 1U << index;
  }
  return 0U;
}

static inline int
cf_v3_ppd_records_need_projection(const uint8_t *input, size_t size,
                                  unsigned int initial_seen)
{
  unsigned int seen = initial_seen;
  size_t offset = 0U;

  while (offset < size)
  {
    size_t line_end = cf_v3_ppd_record_line_end(input, size, offset);
    unsigned int singleton =
        cf_v3_ppd_owned_singleton_bit(input + offset, line_end - offset);

    if (cf_v3_ppd_short_filter_record(input + offset, line_end - offset) ||
        (singleton && (seen & singleton)))
      return 1;
    seen |= singleton;
    offset = line_end;
  }
  return 0;
}

static inline size_t
cf_v3_ppd_copy_deploy_records(uint8_t *output, const uint8_t *input,
                              size_t size, unsigned int initial_seen)
{
  unsigned int seen = initial_seen;
  size_t input_offset = 0U;
  size_t output_offset = 0U;

  while (input_offset < size)
  {
    size_t line_end =
        cf_v3_ppd_record_line_end(input, size, input_offset);
    size_t line_size = line_end - input_offset;
    unsigned int singleton =
        cf_v3_ppd_owned_singleton_bit(input + input_offset, line_size);

    if (!cf_v3_ppd_short_filter_record(input + input_offset, line_size) &&
        (!singleton || !(seen & singleton)))
    {
      memcpy(output + output_offset, input + input_offset, line_size);
      output_offset += line_size;
      seen |= singleton;
    }
    input_offset = line_end;
  }
  return output_offset;
}

#endif
