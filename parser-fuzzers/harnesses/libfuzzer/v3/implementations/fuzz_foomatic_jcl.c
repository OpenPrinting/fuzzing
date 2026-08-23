// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include CF_V3_FOOMATIC_RENDERER_SOURCE

#define CF_V3_JCL_MAGIC "JCLV3R01"
#define CF_V3_JCL_MAGIC_SIZE 8U
#define CF_V3_JCL_SELECTORS 24U
#define CF_V3_JCL_MAX_MATERIAL 1024U
#define CF_V3_JCL_MAX_DOCUMENT 131072U
#define CF_V3_JCL_MAX_LINE 1200U
#define CF_V3_JCL_MAX_OPTIONS 64U
#define CF_V3_JCL_OPTION_SIZE 192U
#define CF_V3_JCL_MAX_OUTPUT (2U * CF_V3_JCL_MAX_DOCUMENT)

typedef struct cf_v3_jcl_buffer_s {
  char *data;
  size_t size;
  size_t capacity;
} cf_v3_jcl_buffer_t;

typedef struct cf_v3_jcl_program_s {
  char document[CF_V3_JCL_MAX_DOCUMENT];
  char payload[2U * CF_V3_JCL_MAX_MATERIAL + 16U];
  char preferred_storage[CF_V3_JCL_MAX_OPTIONS][CF_V3_JCL_OPTION_SIZE];
  char *preferred[CF_V3_JCL_MAX_OPTIONS + 1U];
  const char *marker;
  size_t document_size;
  size_t payload_size;
  unsigned original_count;
  unsigned preferred_count;
} cf_v3_jcl_program_t;

static int cf_v3_jcl_add(cf_v3_jcl_buffer_t *buffer, const void *data,
                         size_t size) {
  if (!buffer || !data || size > buffer->capacity - buffer->size) {
    return 0;
  }
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int cf_v3_jcl_text(cf_v3_jcl_buffer_t *buffer, const char *text) {
  return text && cf_v3_jcl_add(buffer, text, strlen(text));
}

static char cf_v3_jcl_material(const uint8_t *material, size_t material_size,
                               size_t index) {
  return (char)('A' + material[index % material_size] % 26U);
}

static size_t cf_v3_jcl_safe_prefix(unsigned selector) {
  static const uint8_t lengths[] = {0U, 1U, 31U, 63U, 95U, 126U, 127U, 0U};

  return lengths[selector % (sizeof(lengths) / sizeof(lengths[0]))];
}

static size_t cf_v3_jcl_unsafe_prefix(unsigned selector) {
  static const uint16_t lengths[] = {128U, 129U, 146U, 147U, 160U, 255U,
                                     511U, 1023U};

  return lengths[selector % (sizeof(lengths) / sizeof(lengths[0]))];
}

static unsigned cf_v3_jcl_growth_count(unsigned selector) {
  static const uint8_t counts[] = {7U, 8U, 15U, 16U, 31U, 32U, 63U, 64U};

  return counts[selector % (sizeof(counts) / sizeof(counts[0]))];
}

static size_t cf_v3_jcl_growth_length(unsigned selector) {
  static const uint16_t lengths[] = {32U, 127U, 255U, 256U, 257U, 511U,
                                     512U, 1023U};

  return lengths[selector % (sizeof(lengths) / sizeof(lengths[0]))];
}

static int cf_v3_jcl_option(char *buffer, size_t capacity,
                            const char *marker, unsigned key, unsigned value,
                            int enter) {
  static const char *const keys[] = {
    "COPIES", "DUPLEX", "RESOLUTION", "MEDIATYPE", "OUTPUTBIN",
    "ORIENTATION", "COLORSPACE", "QUALITY", "ECONOMODE", "PAPER",
  };
  int length;

  if (enter) {
    length = snprintf(buffer, capacity, "%s ENTER LANGUAGE=POSTSCRIPT",
                      marker);
  } else {
    length = snprintf(buffer, capacity, "%s SET %s=%u", marker,
                      keys[key % (sizeof(keys) / sizeof(keys[0]))],
                      1U + value % 9999U);
  }
  return length >= 0 && (size_t)length < capacity;
}

static int cf_v3_jcl_line(cf_v3_jcl_buffer_t *document, const char *marker,
                          size_t prefix_size, size_t desired_size,
                          unsigned key, unsigned value, int enter, int crlf,
                          const uint8_t *material, size_t material_size) {
  char line[CF_V3_JCL_MAX_LINE];
  size_t used = 0U;

  if (prefix_size + 64U >= sizeof(line)) {
    return 0;
  }
  while (used < prefix_size) {
    line[used] = cf_v3_jcl_material(material, material_size, used + key);
    used++;
  }
  if (!cf_v3_jcl_option(line + used, sizeof(line) - used, marker, key, value,
                        enter)) {
    return 0;
  }
  used += strlen(line + used);
  if (desired_size < used) {
    desired_size = used;
  }
  if (desired_size + 3U > sizeof(line)) {
    return 0;
  }
  while (used < desired_size) {
    line[used] = cf_v3_jcl_material(material, material_size, used + value);
    used++;
  }
  if (crlf) {
    line[used++] = '\r';
  }
  line[used++] = '\n';
  return cf_v3_jcl_add(document, line, used);
}

static int cf_v3_jcl_payload(cf_v3_jcl_program_t *program,
                             cf_v3_jcl_buffer_t *document,
                             const uint8_t *material, size_t material_size,
                             unsigned pattern) {
  static const char hex[] = "0123456789abcdef";
  cf_v3_jcl_buffer_t payload = {
    program->payload, 0U, sizeof(program->payload),
  };

  if (!cf_v3_jcl_text(&payload, "DATA:")) {
    return 0;
  }
  for (size_t index = 0U; index < material_size; index++) {
    size_t source = pattern & 1U ? material_size - index - 1U : index;
    uint8_t value = material[source] ^ (uint8_t)(pattern * 29U);
    char pair[2] = {hex[value >> 4U], hex[value & 15U]};

    if (!cf_v3_jcl_add(&payload, pair, sizeof(pair))) {
      return 0;
    }
  }
  program->payload_size = payload.size;
  return cf_v3_jcl_add(document, payload.data, payload.size);
}

static int cf_v3_jcl_preferred(cf_v3_jcl_program_t *program,
                               unsigned key, unsigned value) {
  if (program->preferred_count >= CF_V3_JCL_MAX_OPTIONS ||
      !cf_v3_jcl_option(
          program->preferred_storage[program->preferred_count],
          sizeof(program->preferred_storage[program->preferred_count]),
          program->marker, key, value, 0)) {
    return 0;
  }
  program->preferred[program->preferred_count] =
      program->preferred_storage[program->preferred_count];
  program->preferred_count++;
  return 1;
}

static int cf_v3_jcl_build_regular(
    cf_v3_jcl_program_t *program, const uint8_t *selector,
    const uint8_t *material, size_t material_size, unsigned mode) {
  static const char *const markers[] = {"@PJL", "@EJL", "@PJL"};
  cf_v3_jcl_buffer_t document = {
    program->document, 0U, sizeof(program->document),
  };
  size_t prefix_size = cf_v3_jcl_safe_prefix(selector[4]);
  unsigned count = mode == 1U ? cf_v3_jcl_growth_count(selector[1])
                              : 1U + selector[1] % 8U;
  size_t long_size = mode == 1U ? cf_v3_jcl_growth_length(selector[3]) : 0U;
  unsigned long_index = count ? selector[14] % count : 0U;

  program->marker = markers[selector[5] % 3U];
  for (unsigned index = 0U; index < count; index++) {
    int enter = selector[9] % (count + 1U) == index;
    size_t line_size = mode == 1U && index == long_index ? long_size : 0U;

    if (!cf_v3_jcl_line(&document, program->marker,
                        index == 0U ? prefix_size : 0U, line_size,
                        selector[7] + index, selector[8] + index, enter,
                        selector[6] & 1U, material, material_size)) {
      return 0;
    }
    program->original_count++;
  }
  for (unsigned index = 0U; index < selector[2] % 8U; index++) {
    if (!cf_v3_jcl_preferred(program, selector[7] + index,
                             selector[8] + index + 17U)) {
      return 0;
    }
  }
  if (!cf_v3_jcl_payload(program, &document, material, material_size,
                         selector[12] % 4U)) {
    return 0;
  }
  program->document_size = document.size;
  return 1;
}

static int cf_v3_jcl_build_actions(
    cf_v3_jcl_program_t *program, const uint8_t *selector,
    const uint8_t *material, size_t material_size) {
  cf_v3_jcl_buffer_t document = {
    program->document, 0U, sizeof(program->document),
  };
  unsigned action_count = 1U + selector[13] % 64U;
  int payload_written = 0;

  program->marker = "@PJL";
  for (unsigned action = 0U; action < action_count; action++) {
    uint8_t opcode = material[action % material_size];
    unsigned kind = opcode % 5U;
    unsigned argument = selector[15U + action % 9U] + opcode;

    if (kind == 0U || kind == 2U) {
      if (!payload_written &&
          !cf_v3_jcl_line(&document, program->marker,
                          program->original_count == 0U
                              ? cf_v3_jcl_safe_prefix(selector[4])
                              : 0U,
                          0U, argument, argument + action, kind == 2U,
                          selector[6] & 1U, material, material_size)) {
        return 0;
      }
      if (!payload_written) {
        program->original_count++;
      }
    } else if (kind == 1U) {
      if (!cf_v3_jcl_preferred(program, argument, argument + action + 1U)) {
        return 0;
      }
    } else if (!payload_written) {
      if (!cf_v3_jcl_payload(program, &document, material, material_size,
                             argument % 4U)) {
        return 0;
      }
      payload_written = 1;
    }
  }
  if (!payload_written &&
      !cf_v3_jcl_payload(program, &document, material, material_size,
                         selector[12] % 4U)) {
    return 0;
  }
  program->document_size = document.size;
  return 1;
}

static int cf_v3_jcl_build_regression(
    cf_v3_jcl_program_t *program, const uint8_t *selector,
    const uint8_t *material, size_t material_size, unsigned mode) {
  cf_v3_jcl_buffer_t document = {
    program->document, 0U, sizeof(program->document),
  };

  program->marker = mode == 3U ? "" : "@PJL";
  if (mode == 3U) {
    if (!cf_v3_jcl_text(&document, "\n")) {
      return 0;
    }
  } else {
    for (unsigned index = 0U; index < 3U; index++) {
      if (!cf_v3_jcl_line(&document, program->marker,
                          index == 0U
                              ? cf_v3_jcl_unsafe_prefix(selector[4])
                              : 0U,
                          0U, index, index + 1U, index == 2U, 0, material,
                          material_size)) {
        return 0;
      }
      program->original_count++;
    }
    if (!cf_v3_jcl_payload(program, &document, material, material_size, 0U)) {
      return 0;
    }
  }
  program->document_size = document.size;
  return 1;
}

static int cf_v3_jcl_contains(const uint8_t *haystack, size_t haystack_size,
                              const char *needle) {
  size_t needle_size = strlen(needle);

  if (!needle_size || needle_size > haystack_size) {
    return 0;
  }
  for (size_t offset = 0U; offset <= haystack_size - needle_size; offset++) {
    if (memcmp(haystack + offset, needle, needle_size) == 0) {
      return 1;
    }
  }
  return 0;
}

static size_t cf_v3_jcl_run(cf_v3_jcl_program_t *program,
                            uint8_t output_data[CF_V3_JCL_MAX_OUTPUT],
                            unsigned mode) {
  FILE *input = NULL;
  FILE *output = NULL;
  char **lines = NULL;
  size_t last_line_size = 0U;
  long output_size = 0L;

  input = fmemopen((void *)program->document, program->document_size, "rb");
  if (!input) {
    return 0U;
  }
  lines = read_jcl_lines(input, program->marker, &last_line_size);
  if (!lines) {
    fclose(input);
    return 0U;
  }
  if (mode < 3U &&
      (argv_count(lines) != program->original_count + 1U ||
       last_line_size != program->payload_size ||
       memcmp(lines[program->original_count], program->payload,
              program->payload_size) != 0)) {
    __builtin_trap();
  }

  output = tmpfile();
  if (!output) {
    argv_free(lines);
    fclose(input);
    return 0U;
  }
  (void)write_merged_jcl_options(output, lines, program->preferred,
                                 last_line_size, program->marker);
  if (fflush(output) != 0 || fseek(output, 0L, SEEK_END) != 0 ||
      (output_size = ftell(output)) < 0 ||
      (size_t)output_size > CF_V3_JCL_MAX_OUTPUT ||
      fseek(output, 0L, SEEK_SET) != 0 ||
      fread(output_data, 1U, (size_t)output_size, output) !=
          (size_t)output_size) {
    __builtin_trap();
  }
  if (mode < 3U) {
    if ((size_t)output_size < program->payload_size ||
        memcmp(output_data + (size_t)output_size - program->payload_size,
               program->payload, program->payload_size) != 0) {
      __builtin_trap();
    }
    for (unsigned index = 0U; index < program->preferred_count; index++) {
      int duplicate = 0;

      for (unsigned prior = 0U; prior < index; prior++) {
        if (jcl_keywords_equal(program->preferred[prior],
                               program->preferred[index], program->marker)) {
          duplicate = 1;
          break;
        }
      }
      if (!duplicate &&
          !cf_v3_jcl_contains(output_data, (size_t)output_size,
                              program->preferred[index])) {
        __builtin_trap();
      }
    }
  }

  fclose(output);
  argv_free(lines);
  fclose(input);
  return (size_t)output_size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t fixed_size = CF_V3_JCL_MAGIC_SIZE + CF_V3_JCL_SELECTORS;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;
  cf_v3_jcl_program_t program = {0};
  uint8_t first[CF_V3_JCL_MAX_OUTPUT];
  uint8_t second[CF_V3_JCL_MAX_OUTPUT];
  unsigned mode;
  size_t first_size;
  size_t second_size;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V3_JCL_MAX_MATERIAL ||
      memcmp(data, CF_V3_JCL_MAGIC, CF_V3_JCL_MAGIC_SIZE) != 0) {
    return 0;
  }
  selector = data + CF_V3_JCL_MAGIC_SIZE;
  material = data + fixed_size;
  material_size = size - fixed_size;
  mode = selector[0];
  if (mode > 4U) {
    return 0;
  }

  if (mode < 2U) {
    if (!cf_v3_jcl_build_regular(&program, selector, material, material_size,
                                 mode)) {
      return 0;
    }
  } else if (mode == 2U) {
    if (!cf_v3_jcl_build_actions(&program, selector, material,
                                 material_size)) {
      return 0;
    }
  } else if (!cf_v3_jcl_build_regression(&program, selector, material,
                                         material_size, mode)) {
    return 0;
  }
  program.preferred[program.preferred_count] = NULL;

  first_size = cf_v3_jcl_run(&program, first, mode);
  if (mode >= 3U) {
    return 0;
  }
  second_size = cf_v3_jcl_run(&program, second, mode);
  if (first_size == 0U || first_size != second_size ||
      memcmp(first, second, first_size) != 0) {
    __builtin_trap();
  }
  return 0;
}
