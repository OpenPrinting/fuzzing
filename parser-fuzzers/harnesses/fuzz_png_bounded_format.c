#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define LLVMFuzzerTestOneInput cf_fuzz_png_unbounded_test_one_input
#include "fuzz_cupsfilters_image_codec.c"
#undef LLVMFuzzerTestOneInput

static uint32_t cf_fuzz_png_chunk_length(const uint8_t *data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) | data[3];
}

static int cf_fuzz_png_chunks_fit_input(const uint8_t *data, size_t size) {
  static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n',
                                       0x1a, '\n'};
  size_t offset = sizeof(signature);

  if (!data || size < sizeof(signature) ||
      memcmp(data, signature, sizeof(signature)) != 0) {
    return 0;
  }

  while (offset <= size && size - offset >= 12U) {
    uint32_t length = cf_fuzz_png_chunk_length(data + offset);
    const uint8_t *type = data + offset + 4U;

    if ((size_t)length > size - offset - 12U) {
      return 0;
    }
    offset += (size_t)length + 12U;
    if (memcmp(type, "IEND", 4U) == 0) {
      return 1;
    }
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!cf_fuzz_png_chunks_fit_input(data, size)) {
    return 0;
  }
  return cf_fuzz_png_unbounded_test_one_input(data, size);
}
