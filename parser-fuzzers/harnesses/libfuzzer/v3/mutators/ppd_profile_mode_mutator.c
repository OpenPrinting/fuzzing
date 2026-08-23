// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PPD_PROFILE_MAGIC "PPDPROF1"
#define CF_V3_PPD_PROFILE_MAGIC_SIZE 8U
#define CF_V3_PPD_PROFILE_MIN_STATE (1U + CF_V3_PPD_PROFILE_MAGIC_SIZE + 16U)
#define CF_V3_PPD_PROFILE_MAX_STATE (CF_V3_PPD_PROFILE_MIN_STATE + 64U)

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t cf_v3_profile_random(uint32_t *state) {
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static size_t cf_v3_profile_repair_state(uint8_t *data, size_t size,
                                         size_t max_size, uint32_t *state) {
  size_t bounded_max = max_size < CF_V3_PPD_PROFILE_MAX_STATE
                           ? max_size
                           : CF_V3_PPD_PROFILE_MAX_STATE;

  if (bounded_max < CF_V3_PPD_PROFILE_MIN_STATE) {
    return 0U;
  }
  if (size < CF_V3_PPD_PROFILE_MIN_STATE) {
    for (size_t index = size; index < CF_V3_PPD_PROFILE_MIN_STATE; index++) {
      data[index] = (uint8_t)cf_v3_profile_random(state);
    }
    size = CF_V3_PPD_PROFILE_MIN_STATE;
  }
  if (size > bounded_max) {
    size = bounded_max;
  }
  data[0] = 0U;
  memcpy(data + 1U, CF_V3_PPD_PROFILE_MAGIC,
         CF_V3_PPD_PROFILE_MAGIC_SIZE);
  return size;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  uint32_t state = seed;
  size_t payload_size;

  if (!data || max_size < 2U) {
    return 0U;
  }
  if (size < 2U) {
    data[0] = (uint8_t)(cf_v3_profile_random(&state) & 1U);
    data[1] = (uint8_t)cf_v3_profile_random(&state);
    size = 2U;
  }
  data[0] &= 1U;
  if ((cf_v3_profile_random(&state) & 15U) == 0U) {
    data[0] ^= 1U;
  }

  if (data[0] == 0U) {
    size = cf_v3_profile_repair_state(data, size, max_size, &state);
    if (!size) {
      return 0U;
    }
    payload_size = LLVMFuzzerMutate(
        data + 1U + CF_V3_PPD_PROFILE_MAGIC_SIZE,
        size - 1U - CF_V3_PPD_PROFILE_MAGIC_SIZE,
        (max_size < CF_V3_PPD_PROFILE_MAX_STATE
             ? max_size
             : CF_V3_PPD_PROFILE_MAX_STATE) -
            1U - CF_V3_PPD_PROFILE_MAGIC_SIZE);
    size = payload_size + 1U + CF_V3_PPD_PROFILE_MAGIC_SIZE;
    return cf_v3_profile_repair_state(data, size, max_size, &state);
  }

  payload_size = LLVMFuzzerMutate(data + 1U, size - 1U, max_size - 1U);
  if (!payload_size) {
    data[1] = (uint8_t)cf_v3_profile_random(&state);
    payload_size = 1U;
  }
  data[0] = 1U;
  return payload_size + 1U;
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                  const uint8_t *data2, size_t size2,
                                  uint8_t *out, size_t max_out_size,
                                  unsigned int seed) {
  const uint8_t *source = (seed & 1U) && size2 >= 2U ? data2 : data1;
  size_t source_size = source == data1 ? size1 : size2;
  uint32_t state = seed;

  if (!out || max_out_size < 2U || (size1 < 2U && size2 < 2U)) {
    return 0U;
  }
  if (source_size < 2U) {
    source = source == data1 ? data2 : data1;
    source_size = source == data1 ? size1 : size2;
  }
  if (source_size > max_out_size) {
    source_size = max_out_size;
  }
  memcpy(out, source, source_size);
  out[0] &= 1U;
  if (out[0] == 0U) {
    return cf_v3_profile_repair_state(out, source_size, max_out_size, &state);
  }
  return source_size;
}
