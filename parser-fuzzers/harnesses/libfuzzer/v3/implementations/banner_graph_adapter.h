// SPDX-License-Identifier: Apache-2.0
#ifndef CF_V3_BANNER_GRAPH_ADAPTER_H
#define CF_V3_BANNER_GRAPH_ADAPTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CF_V3_BANNER_GRAPH_MAX_CONTENT (1024U * 1024U)

bool cf_v3_banner_graph_build(const uint8_t *data, size_t size,
                              char path[1024], uint8_t *expected,
                              size_t expected_capacity,
                              size_t *expected_length,
                              bool *valid_media_box);

bool cf_v3_banner_graph_validate(const char *path, const uint8_t *data,
                                 size_t size, const uint8_t *expected,
                                 size_t expected_length,
                                 unsigned expected_pages);

#endif
