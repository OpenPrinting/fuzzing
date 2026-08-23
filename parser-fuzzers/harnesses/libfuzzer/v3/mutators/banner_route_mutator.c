// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

#define CF_V3_BANNER_HEADER_BYTES 37U
#define CF_V3_BANNER_STRUCTURED_MAX 101U

static uint32_t cf_v3_banner_random(uint32_t *state) {
  uint32_t value = *state ? *state : 0x9e3779b9U;
  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  uint32_t state = seed;
  unsigned route;

  if (!max_size) {
    return 0U;
  }
  if (!size) {
    data[0] = 0U;
    size = 1U;
  }
  route = data[0] % 3U;
  if (route == 0U) {
    const size_t structured_limit =
        max_size < CF_V3_BANNER_STRUCTURED_MAX
            ? max_size
            : CF_V3_BANNER_STRUCTURED_MAX;
    if (structured_limit < CF_V3_BANNER_HEADER_BYTES) {
      data[0] = 1U;
      return LLVMFuzzerMutate(data, size, max_size);
    }
    if (size < CF_V3_BANNER_HEADER_BYTES) {
      memset(data + size, 0, CF_V3_BANNER_HEADER_BYTES - size);
      size = CF_V3_BANNER_HEADER_BYTES;
    }
    if (size > structured_limit) {
      size = structured_limit;
    }
    if (cf_v3_banner_random(&state) % 5U < 4U) {
      const size_t field = 1U +
          cf_v3_banner_random(&state) % (CF_V3_BANNER_HEADER_BYTES - 1U);
      data[field] ^= (uint8_t)(1U << (cf_v3_banner_random(&state) & 7U));
    } else {
      size_t material_size = size - CF_V3_BANNER_HEADER_BYTES;
      material_size = LLVMFuzzerMutate(
          data + CF_V3_BANNER_HEADER_BYTES, material_size,
          structured_limit - CF_V3_BANNER_HEADER_BYTES);
      size = CF_V3_BANNER_HEADER_BYTES + material_size;
    }
    if (cf_v3_banner_random(&state) % 128U == 0U) {
      data[0] = 1U + cf_v3_banner_random(&state) % 2U;
    } else {
      data[0] = 0U;
    }
    return size;
  }

  if (size == 1U && max_size > 1U) {
    data[1] = 0U;
    size = 2U;
  }
  size = 1U + LLVMFuzzerMutate(data + 1U, size - 1U, max_size - 1U);
  data[0] = (uint8_t)route;
  if (cf_v3_banner_random(&state) % 128U == 0U &&
      max_size >= CF_V3_BANNER_HEADER_BYTES) {
    if (size < CF_V3_BANNER_HEADER_BYTES) {
      memset(data + size, 0, CF_V3_BANNER_HEADER_BYTES - size);
      size = CF_V3_BANNER_HEADER_BYTES;
    }
    data[0] = 0U;
  }
  return size;
}
