// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PPD_PROFILE_MAX_INPUT (32U * 1024U + 1U)

extern int __real_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern int cf_v3_ppd_profile_deep_raw(const uint8_t *data, size_t size);
extern int cf_v3_ppd_profile_faithful_raw(const uint8_t *data, size_t size);

static int cf_v3_ppd_profile_keyword_matches(const uint8_t *data,
                                             size_t start, size_t end,
                                             const char *keyword) {
  size_t keyword_index = 0U;
  size_t keyword_size = strlen(keyword);

  for (size_t index = start; index < end; index++) {
    /* ppd_read() drops DOS EOF (0x1a) before parsing the keyword. */
    if (data[index] == 0x1aU) {
      continue;
    }
    if (keyword_index >= keyword_size ||
        data[index] != (uint8_t)keyword[keyword_index++]) {
      return 0;
    }
  }
  return keyword_index == keyword_size;
}

static int cf_v3_ppd_profile_singletons_are_unique(const uint8_t *data,
                                                   size_t size) {
  static const char *const keywords[] = {
      "LanguageEncoding", "NickName", "JCLBegin",
      "JCLEnd", "JCLToPSInterpreter", "JCLToPDFInterpreter",
  };
  unsigned seen[sizeof(keywords) / sizeof(keywords[0])] = {0U};
  size_t line = 0U;

  while (line < size) {
    size_t end = line;
    size_t name_start;
    size_t name_end;

    while (end < size && data[end] != '\n' && data[end] != '\r') {
      end++;
    }
    name_start = line;
    while (name_start < end &&
           (data[name_start] == ' ' || data[name_start] == '\t')) {
      name_start++;
    }
    if (name_start < end && data[name_start] == '*') {
      name_start++;
      name_end = name_start;
      while (name_end < end && data[name_end] != ':' &&
             data[name_end] != ' ' && data[name_end] != '\t') {
        name_end++;
      }
      for (size_t index = 0U;
           index < sizeof(keywords) / sizeof(keywords[0]); index++) {
        if (cf_v3_ppd_profile_keyword_matches(
                data, name_start, name_end, keywords[index]) &&
            ++seen[index] > 1U) {
          return 0;
        }
      }
    }
    line = end;
    while (line < size && (data[line] == '\n' || data[line] == '\r')) {
      line++;
    }
  }
  return 1;
}

int __wrap_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!data || size < 2U || size > CF_V3_PPD_PROFILE_MAX_INPUT) {
    return 0;
  }
  if (data[0] == 0U) {
    return __real_LLVMFuzzerTestOneInput(data + 1U, size - 1U);
  }
  if (data[0] == 1U) {
    if (!cf_v3_ppd_profile_singletons_are_unique(data + 1U, size - 1U)) {
      return 0;
    }
    return cf_v3_ppd_profile_deep_raw(data + 1U, size - 1U);
  }
  if (data[0] == 2U) {
    return cf_v3_ppd_profile_faithful_raw(data + 1U, size - 1U);
  }
  return 0;
}
