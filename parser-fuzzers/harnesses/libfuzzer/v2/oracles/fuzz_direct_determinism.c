// SPDX-License-Identifier: Apache-2.0
#include "../include/control.h"
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef CF_V2_MAX_DOCUMENT
#define CF_V2_MAX_DOCUMENT (2U * 1024U * 1024U)
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_control_t control;
  cf_v2_run_result_t first;
  cf_v2_run_result_t second;
  const uint8_t *document;
  size_t document_size;
  int first_ok;
  int second_ok;

  if (!cf_v2_split_input(data, size, CF_V2_MAX_DOCUMENT, &document,
                         &document_size, &control)) {
    return 0;
  }
  first_ok = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &first);
  second_ok = cf_v2_execute_direct(document, document_size, &control, 1,
                                   &second);
  if (first_ok && second_ok && first.captured && second.captured &&
      (first.status != second.status ||
       first.output_size != second.output_size ||
       (first.output_size &&
        memcmp(first.output, second.output, first.output_size) != 0))) {
    __builtin_trap();
  }
  cf_v2_free_run_result(&first);
  cf_v2_free_run_result(&second);
  return 0;
}
