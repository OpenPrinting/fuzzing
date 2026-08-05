#include <stddef.h>
#include <stdint.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

#ifndef CF_FUZZ_STATE_PREFIX_SIZE
#define CF_FUZZ_STATE_PREFIX_SIZE 0U
#endif

#ifndef CF_FUZZ_STATE_SELECTOR_SIZE
#error "CF_FUZZ_STATE_SELECTOR_SIZE must name the compact state selector bytes"
#endif

#ifndef CF_FUZZ_STATE_MIN_PAYLOAD
#define CF_FUZZ_STATE_MIN_PAYLOAD 0U
#endif

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t state_size =
      CF_FUZZ_STATE_PREFIX_SIZE + CF_FUZZ_STATE_SELECTOR_SIZE;
  size_t payload_size;
  size_t mutated_size;

  if (!data || size < state_size + CF_FUZZ_STATE_MIN_PAYLOAD ||
      max_size < state_size + CF_FUZZ_STATE_MIN_PAYLOAD)
    return LLVMFuzzerMutate(data, size, max_size);

  /* Selector bytes are total functions: every value maps to a finite state. */
  if ((seed & 3U) != 0U)
  {
    const size_t slot = CF_FUZZ_STATE_PREFIX_SIZE +
                        ((seed >> 2U) % CF_FUZZ_STATE_SELECTOR_SIZE);
    const uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      data[slot] ^= delta;
    else
      data[slot] += delta;
    return size;
  }

  payload_size = size - state_size;
  mutated_size = LLVMFuzzerMutate(data + state_size, payload_size,
                                  max_size - state_size);
  if (mutated_size < CF_FUZZ_STATE_MIN_PAYLOAD)
  {
    data[state_size] = (uint8_t)seed;
    mutated_size = CF_FUZZ_STATE_MIN_PAYLOAD;
  }
  return state_size + mutated_size;
}
