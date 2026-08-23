// SPDX-License-Identifier: Apache-2.0
#include "../../v2/include/control.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CF_V3_COMMAND_MAGIC "CMDV3R01"
#define CF_V3_COMMAND_MAGIC_SIZE 8U
#define CF_V3_COMMAND_SELECTORS 24U
#define CF_V3_COMMAND_MAX_PAYLOAD (16U * 1024U)
#define CF_V3_COMMAND_CAPACITY (CF_V3_COMMAND_MAX_PAYLOAD + 32U)

typedef struct cf_v3_command_document_s {
  uint8_t data[CF_V3_COMMAND_CAPACITY + CF_V2_CONTROL_SIZE];
  size_t size;
} cf_v3_command_document_t;

extern int cf_v3_command_legacy_entry(const uint8_t *data, size_t size);
extern int cf_v3_command_oracle_entry(const uint8_t *data, size_t size);

static int cf_v3_command_add(cf_v3_command_document_t *document,
                             const void *data, size_t size) {
  if (size > CF_V3_COMMAND_CAPACITY - document->size) {
    return 0;
  }
  memcpy(document->data + document->size, data, size);
  document->size += size;
  return 1;
}

static int cf_v3_command_text(cf_v3_command_document_t *document,
                              const char *text) {
  return cf_v3_command_add(document, text, strlen(text));
}

static int cf_v3_command_case(cf_v3_command_document_t *document,
                              const char *text, unsigned mode) {
  for (size_t index = 0U; text[index]; index++) {
    uint8_t value = (uint8_t)text[index];

    if (mode == 1U) {
      value = (uint8_t)toupper(value);
    } else if (mode == 2U) {
      value = (uint8_t)tolower(value);
    } else if (mode == 3U && (index & 1U)) {
      value = (uint8_t)toupper(value);
    }
    if (!cf_v3_command_add(document, &value, 1U)) {
      return 0;
    }
  }
  return 1;
}

static int cf_v3_command_newline(cf_v3_command_document_t *document,
                                 unsigned mode) {
  static const char *const endings[] = {"\n", "\r\n", "\n", "\n"};

  return cf_v3_command_text(document, endings[mode % 4U]);
}

static int cf_v3_command_header(
    cf_v3_command_document_t *document,
    const uint8_t selector[CF_V3_COMMAND_SELECTORS], unsigned relation) {
  unsigned mode = relation == 1U ? selector[16] % 4U : 0U;

  if (mode == 0U) {
    return cf_v3_command_text(document, "#CUPS-COMMAND") &&
           cf_v3_command_newline(document, selector[20]);
  }
  if (mode == 1U) {
    return cf_v3_command_text(document, "#CUPS") &&
           cf_v3_command_newline(document, selector[20]);
  }
  if (mode == 2U) {
    return cf_v3_command_text(document, "#cups-command") &&
           cf_v3_command_newline(document, selector[20]);
  }
  return 1;
}

static int cf_v3_command_line(
    cf_v3_command_document_t *document,
    const uint8_t selector[CF_V3_COMMAND_SELECTORS], const uint8_t *payload,
    size_t payload_size, unsigned line) {
  static const char *const commands[] = {
    "Clean", "PrintAlignmentPage", "PrintSelfTestPage", "ReportLevels",
    "SetAlignment", "UnknownCommand", "CleanHeads", "ReportLevelsNow",
  };
  unsigned command = (selector[1] + line * (1U + selector[6])) % 8U;
  size_t material_size = 1U + (selector[10] + line) % 32U;
  char number[64];
  int length;

  if ((selector[7] + line) % 4U == 0U) {
    if (!cf_v3_command_text(document, "# ")) {
      return 0;
    }
  } else if (!cf_v3_command_case(document, commands[command], selector[4])) {
    return 0;
  }
  if (command == 1U || command == 4U) {
    length = snprintf(number, sizeof(number), " %d",
                      (int)((selector[15] + line * 17U) & 255U));
    if (length <= 0 || (size_t)length >= sizeof(number) ||
        !cf_v3_command_add(document, number, (size_t)length)) {
      return 0;
    }
  }
  if (command == 4U) {
    length = snprintf(number, sizeof(number), " %d",
                      (int)selector[2] * 31 - 63);
    if (length <= 0 || (size_t)length >= sizeof(number) ||
        !cf_v3_command_add(document, number, (size_t)length)) {
      return 0;
    }
  } else if (command >= 5U) {
    if (!cf_v3_command_text(document, selector[3] & 1U ? "\t" : " ")) {
      return 0;
    }
    for (size_t index = 0U; index < material_size; index++) {
      uint8_t value =
          (uint8_t)('!' + payload[(index + line) % payload_size] % 94U);
      if (!cf_v3_command_add(document, &value, 1U)) {
        return 0;
      }
    }
  }
  return 1;
}

static int cf_v3_command_relation(
    cf_v3_command_document_t *document,
    const uint8_t selector[CF_V3_COMMAND_SELECTORS], unsigned relation) {
  uint8_t zero = 0U;

  switch (relation) {
    case 2U:
      return cf_v3_command_text(document, "Clean") &&
             cf_v3_command_add(document, &zero, 1U) &&
             cf_v3_command_text(document, "Tail\n");
    case 3U: {
      size_t count = 2047U + (selector[17] % 4U) * 1024U;

      while (count--) {
        if (!cf_v3_command_text(document, "A")) {
          return 0;
        }
      }
      return cf_v3_command_newline(document, selector[20]);
    }
    case 4U:
      return cf_v3_command_text(document, "Clean\rReportLevels");
    case 5U:
      return cf_v3_command_text(document, " \t\r\v\fClean\n");
    case 6U:
      return cf_v3_command_text(
          document, "SetAlignment +2147483647 -2147483648\n");
    default:
      return 1;
  }
}

static int cf_v3_command_raw(cf_v3_command_document_t *document,
                             const uint8_t *payload, size_t payload_size) {
  for (size_t index = 0U; index < payload_size; index++) {
    uint8_t value = payload[index] ? payload[index] : (uint8_t)' ';

    if (!cf_v3_command_add(document, &value, 1U)) {
      return 0;
    }
  }
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t fixed_size = CF_V3_COMMAND_MAGIC_SIZE + CF_V3_COMMAND_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  cf_v3_command_document_t document = {{0}, 0U};
  cf_v2_control_t control = {0};
  unsigned relation;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V3_COMMAND_MAX_PAYLOAD ||
      memcmp(data, CF_V3_COMMAND_MAGIC, CF_V3_COMMAND_MAGIC_SIZE) != 0) {
    return 0;
  }
  selector = data + CF_V3_COMMAND_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  relation = selector[23];
  if (relation > 8U) {
    return 0;
  }

  if (relation == 7U) {
    if (!cf_v3_command_raw(&document, payload, payload_size)) {
      return 0;
    }
  } else if (relation == 8U) {
    const uint8_t zero = 0U;

    if (!cf_v3_command_add(&document, &zero, 1U) ||
        !cf_v3_command_add(&document, payload, payload_size)) {
      return 0;
    }
  } else {
    unsigned line_count;

    if (!cf_v3_command_header(&document, selector, relation)) {
      return 0;
    }
    line_count = 1U + selector[0] % 8U;
    for (unsigned line = 0U; line < line_count; line++) {
      if (!cf_v3_command_line(&document, selector, payload, payload_size,
                              line) ||
          !cf_v3_command_newline(&document, selector[20])) {
        return 0;
      }
    }
    if (!cf_v3_command_relation(&document, selector, relation)) {
      return 0;
    }
  }

  control.ppd_profile = selector[0];
  control.page_size = selector[18];
  control.resolution = selector[19];
  control.copies = selector[21];
  control.route_mode = selector[22];
  cf_v2_apply_control_policy(&control);

  if (relation == 0U && document.size + 1U <= CF_V3_COMMAND_CAPACITY) {
    uint8_t oracle_document[CF_V3_COMMAND_CAPACITY + 1U];

    oracle_document[0] = (uint8_t)(selector[0] != 0U);
    memcpy(oracle_document + 1U, document.data, document.size);
    return cf_v3_command_oracle_entry(oracle_document, document.size + 1U);
  }

  memcpy(document.data + document.size, &control, sizeof(control));
  return cf_v3_command_legacy_entry(document.data,
                                    document.size + sizeof(control));
}
