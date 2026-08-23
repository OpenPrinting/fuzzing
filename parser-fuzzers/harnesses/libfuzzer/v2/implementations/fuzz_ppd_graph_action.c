// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_ppd_graph_unused_entry
#define LIBPPD_SEMANTIC_MAX_INPUT (64U * 1024U)
#include "../../fuzz_libppd_semantic.c"
#undef LLVMFuzzerTestOneInput

#include "../include/ppd_graph_relation.h"
#include "../include/runtime.h"

#include <cups/raster.h>
#include <ppd/ppd.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V2_PPD_GRAPH_MAX_INPUT \
  (CF_V2_PPD_GRAPH_MAGIC_SIZE + CF_V2_PPD_GRAPH_HEADER_SIZE + 256U)
#define CF_V2_PPD_GRAPH_TEXT_SIZE (64U * 1024U)
#define CF_V2_PPD_GRAPH_MAX_FILTERS 8U
#define CF_V2_PPD_GRAPH_MAX_CHOICES 32U
#define CF_V2_PPD_GRAPH_MAX_PARAMS 32U
#define CF_V2_PPD_GRAPH_MAX_ITEMS 32U

#ifndef CF_V2_PPD_GRAPH_KIND_MASK
#define CF_V2_PPD_GRAPH_KIND_MASK CF_V2_OBJECT_KIND_MASK_ALL
#endif

#ifndef CF_V2_PPD_GRAPH_UNIQUE_REFERENCES
#define CF_V2_PPD_GRAPH_UNIQUE_REFERENCES 0
#endif

typedef struct cf_v2_ppd_graph_buffer_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v2_ppd_graph_buffer_t;

typedef struct cf_v2_ppd_graph_player_s {
  const char *path;
  ppd_file_t *ppd;
  const cf_v2_ppd_graph_relation_t *graph;
  size_t node_count;
  uint64_t hash;
} cf_v2_ppd_graph_player_t;

static cf_v2_relation_stats_t cf_v2_ppd_graph_stats;

static int
cf_v2_ppd_graph_kind_enabled(cf_v2_object_kind_t kind)
{
  return (CF_V2_PPD_GRAPH_KIND_MASK &
          CF_V2_OBJECT_KIND_BIT(kind)) != 0U;
}

static const char *
cf_v2_ppd_graph_stats_name(void)
{
#ifdef CF_V2_PPD_GRAPH_DEEP
  return "ppd-graph-action-deep";
#else
  switch (CF_V2_PPD_GRAPH_KIND_MASK) {
    case CF_V2_OBJECT_KIND_BIT(CF_V2_OBJECT_SCALAR):
      return "ppd-graph-scalar";
    case CF_V2_OBJECT_KIND_BIT(CF_V2_OBJECT_DICTIONARY):
      return "ppd-graph-dictionary";
    case CF_V2_OBJECT_KIND_BIT(CF_V2_OBJECT_STREAM):
      return "ppd-graph-stream";
    case CF_V2_OBJECT_KIND_BIT(CF_V2_OBJECT_OPAQUE):
      return "ppd-graph-opaque";
    default:
      return "ppd-graph-action-faithful";
  }
#endif
}

static int
cf_v2_ppd_graph_append_bytes(cf_v2_ppd_graph_buffer_t *buffer,
                             const void *data, size_t size)
{
  if (!buffer || !data || size > buffer->capacity - buffer->size)
    return 0;
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int
cf_v2_ppd_graph_append(cf_v2_ppd_graph_buffer_t *buffer,
                       const char *format, ...)
{
  va_list args;
  int length;

  if (!buffer || buffer->size >= buffer->capacity)
    return 0;
  va_start(args, format);
  length = vsnprintf((char *)buffer->data + buffer->size,
                     buffer->capacity - buffer->size, format, args);
  va_end(args);
  if (length < 0 || (size_t)length >= buffer->capacity - buffer->size)
    return 0;
  buffer->size += (size_t)length;
  return 1;
}

static size_t
cf_v2_ppd_graph_cardinality(const cf_v2_ppd_graph_node_t *node,
                            size_t limit)
{
  cf_v2_cardinality_relation_t relation;
  size_t value;

  if (!node)
    return 0U;
  relation = node->cardinality;
  relation.boundary = 20U;
  relation.limit = limit;
  value = cf_v2_cardinality_value(&relation);
  return value > limit ? limit : value;
}

static const char *
cf_v2_ppd_graph_option_type(const cf_v2_ppd_graph_relation_t *graph)
{
  static const char *const values[] = {"PickOne", "Boolean", "PickMany"};

  return values[graph->option_type %
                (sizeof(values) / sizeof(values[0]))];
}

static const char *
cf_v2_ppd_graph_custom_type(const cf_v2_ppd_graph_relation_t *graph,
                            uint32_t object_id)
{
  static const char *const values[] = {
    "points", "int", "real", "curve", "invcurve",
    "passcode", "password", "string", "real",
  };
  size_t index = ((size_t)graph->custom_type + object_id) %
                 (sizeof(values) / sizeof(values[0]));

#ifdef CF_V2_PPD_GRAPH_DEEP
  (void)object_id;
  if (index == 7U)
    return "points";
#endif
  return values[index];
}

static int64_t
cf_v2_ppd_graph_exponent(const cf_v2_ppd_graph_relation_t *graph)
{
  int64_t exponent = cf_v2_scalar_relation_value(&graph->numeric_exponent);

  if (exponent < 0)
    exponent = -exponent;
  exponent %= 39;
#ifdef CF_V2_PPD_GRAPH_DEEP
  if (exponent > 6)
    exponent = 6;
#endif
  return exponent;
}

static void
cf_v2_ppd_graph_numeric(char *value, size_t capacity,
                        const cf_v2_ppd_graph_relation_t *graph)
{
  int64_t exponent = cf_v2_ppd_graph_exponent(graph);

  switch (graph->numeric_kind % 6U) {
    case 0U:
      snprintf(value, capacity, "0");
      break;
    case 1U:
      snprintf(value, capacity, "1");
      break;
    case 2U:
      snprintf(value, capacity, "-1");
      break;
    case 3U:
      snprintf(value, capacity, "1e%lld", (long long)exponent);
      break;
    case 4U:
      snprintf(value, capacity, "-1e%lld", (long long)exponent);
      break;
    default:
      snprintf(value, capacity, "9e%lld", (long long)exponent);
      break;
  }
}

static uint32_t
cf_v2_ppd_graph_resolved_reference(const cf_v2_ppd_graph_node_t *node)
{
  return node->reference_mode == CF_V2_RELATION_DERIVED ?
             node->object.object_id : node->reference.referenced_id;
}

static int
cf_v2_ppd_graph_option_key(const cf_v2_ppd_graph_node_t *node,
                           uint32_t *key)
{
  if (node->object.kind == CF_V2_OBJECT_SCALAR)
    *key = node->object.object_id;
  else if (node->object.kind == CF_V2_OBJECT_DICTIONARY)
    *key = cf_v2_ppd_graph_resolved_reference(node);
  else
    return 0;
  return 1;
}

static int
cf_v2_ppd_graph_node_enabled(const cf_v2_ppd_graph_relation_t *graph,
                             size_t index)
{
  const cf_v2_ppd_graph_node_t *node = graph->nodes + index;

  if (!cf_v2_ppd_graph_kind_enabled(node->object.kind))
    return 0;
#if CF_V2_PPD_GRAPH_UNIQUE_REFERENCES
  for (size_t previous = 0U; previous < index; previous ++) {
    const cf_v2_ppd_graph_node_t *candidate = graph->nodes + previous;
    uint32_t candidate_key;
    uint32_t node_key;

    if (!cf_v2_ppd_graph_kind_enabled(candidate->object.kind))
      continue;
    if (node->object.kind == CF_V2_OBJECT_ARRAY &&
        candidate->object.kind == CF_V2_OBJECT_ARRAY)
      return 0;
    if (cf_v2_ppd_graph_option_key(node, &node_key) &&
        cf_v2_ppd_graph_option_key(candidate, &candidate_key) &&
        node_key == candidate_key)
      return 0;
  }
#endif
  return 1;
}

static int
cf_v2_ppd_graph_append_regular(cf_v2_ppd_graph_buffer_t *buffer,
                               const cf_v2_ppd_graph_relation_t *graph,
                               const cf_v2_ppd_graph_node_t *node)
{
  size_t count = cf_v2_ppd_graph_cardinality(
      node, CF_V2_PPD_GRAPH_MAX_CHOICES);
  uint32_t selected = cf_v2_ppd_graph_resolved_reference(node);
  size_t index;

#ifdef CF_V2_PPD_GRAPH_DEEP
  if (cf_v2_scalar_relation_value(&graph->foomatic) && !count)
    count = 1U;
#endif
  if (node->reference_mode == CF_V2_RELATION_DERIVED && count)
    selected = node->object.object_id;
  if (!cf_v2_ppd_graph_append(
          buffer,
          "*OpenUI *Option%u/Graph option %u: %s\n"
          "*OrderDependency: 60 AnySetup *Option%u\n"
          "*DefaultOption%u: Choice%u\n",
          node->object.object_id, node->object.object_id,
          cf_v2_ppd_graph_option_type(graph), node->object.object_id,
          node->object.object_id, selected))
    return 0;
  for (index = 0U; index < count; index ++)
    if (!cf_v2_ppd_graph_append(
            buffer, "*Option%u Choice%u/Choice %u: \"\"\n",
            node->object.object_id,
            (unsigned)(node->object.object_id + index),
            (unsigned)(node->object.object_id + index)))
      return 0;
  return cf_v2_ppd_graph_append(buffer, "*CloseUI: *Option%u\n",
                                node->object.object_id);
}

static int
cf_v2_ppd_graph_append_custom(cf_v2_ppd_graph_buffer_t *buffer,
                              const cf_v2_ppd_graph_relation_t *graph,
                              const cf_v2_ppd_graph_node_t *node)
{
  size_t count = cf_v2_ppd_graph_cardinality(
      node, CF_V2_PPD_GRAPH_MAX_PARAMS);
  uint32_t destination = cf_v2_ppd_graph_resolved_reference(node);
  const char *type = cf_v2_ppd_graph_custom_type(graph,
                                                 node->object.object_id);
  char numeric[32];
  size_t index;

  cf_v2_ppd_graph_numeric(numeric, sizeof(numeric), graph);
  if (node->reference_mode == CF_V2_RELATION_DERIVED) {
    if (!cf_v2_ppd_graph_append(
            buffer,
            "*OpenUI *Option%u/Custom graph option %u: PickOne\n"
            "*DefaultOption%u: Choice%u\n"
            "*Option%u Choice%u/Choice: \"\"\n"
            "*CloseUI: *Option%u\n",
            destination, destination, destination, destination,
            destination, destination, destination))
      return 0;
  }
  if (!cf_v2_ppd_graph_append(buffer,
                              "*CustomOption%u True/Custom: \"pop pop\"\n",
                              destination))
    return 0;
  for (index = 0U; index < count; index ++) {
    if (!strcmp(type, "passcode") || !strcmp(type, "password") ||
        !strcmp(type, "string")) {
      if (!cf_v2_ppd_graph_append(
              buffer,
              "*ParamCustomOption%u P%u/P%u: %u %s 0 80\n",
              destination, (unsigned)(index + 1U),
              (unsigned)(index + 1U), (unsigned)(index + 1U), type))
        return 0;
    } else if (!cf_v2_ppd_graph_append(
                   buffer,
                   "*ParamCustomOption%u P%u/P%u: %u %s -%s %s\n",
                   destination, (unsigned)(index + 1U),
                   (unsigned)(index + 1U), (unsigned)(index + 1U), type,
                   numeric[0] == '-' ? numeric + 1 : numeric, numeric))
      return 0;
  }
  return 1;
}

static int
cf_v2_ppd_graph_append_page_custom(cf_v2_ppd_graph_buffer_t *buffer,
                                   const cf_v2_ppd_graph_relation_t *graph,
                                   const cf_v2_ppd_graph_node_t *node)
{
  static const char *const names[] = {
    "Width", "Height", "WidthOffset", "HeightOffset", "Orientation"
  };
  size_t count = cf_v2_ppd_graph_cardinality(node, 5U);
  const char *type = cf_v2_ppd_graph_custom_type(graph,
                                                 node->object.object_id);
  size_t index;

  if (!cf_v2_ppd_graph_append(buffer, "*VariablePaperSize: True\n"))
    return 0;
  for (index = 0U; index < count; index ++) {
    const char *parameter_type = type;

#ifdef CF_V2_PPD_GRAPH_DEEP
    if (index < 2U)
      parameter_type = "points";
#endif
    if (!cf_v2_ppd_graph_append(
            buffer, "*ParamCustomPageSize %s: %u %s 0 1000\n",
            names[index], (unsigned)(index + 1U), parameter_type))
      return 0;
  }
  return cf_v2_ppd_graph_append(
      buffer, "*CustomPageSize True: \"pop pop pop pop pop\"\n");
}

static int
cf_v2_ppd_graph_append_metadata(cf_v2_ppd_graph_buffer_t *buffer,
                                const cf_v2_ppd_graph_node_t *node)
{
  size_t count = cf_v2_ppd_graph_cardinality(
      node, CF_V2_PPD_GRAPH_MAX_ITEMS);
  size_t index;

#ifdef CF_V2_PPD_GRAPH_DEEP
  if (count > 20U)
    count = 20U;
#endif
  if (!count)
    return 1;
  if (!cf_v2_ppd_graph_append(
          buffer, "*cupsPwgRasterGraph%uSupported: \"",
          node->object.object_id))
    return 0;
  for (index = 0U; index < count; index ++)
    if (!cf_v2_ppd_graph_append(buffer, "%sitem%u",
                                index ? "," : "", (unsigned)index))
      return 0;
  return cf_v2_ppd_graph_append(buffer, "\"\n");
}

static int
cf_v2_ppd_graph_append_filter(cf_v2_ppd_graph_buffer_t *buffer,
                              const cf_v2_ppd_graph_relation_t *graph,
                              const cf_v2_ppd_graph_node_t *node)
{
  size_t count = cf_v2_ppd_graph_cardinality(
      node, CF_V2_PPD_GRAPH_MAX_FILTERS);
  size_t length = cf_v2_length_relation_value(&graph->filter_length);
  char value[256];
  size_t index;

  if (length > sizeof(value) - 1U)
    length = sizeof(value) - 1U;
#ifdef CF_V2_PPD_GRAPH_DEEP
  if (length < 10U)
    length = 10U;
#endif
  for (index = 0U; index < length; index ++)
    value[index] = index == 1U || index == 3U ? ' ' :
                   (index == 2U ? '0' : (char)('a' + index % 26U));
  value[length] = '\0';
  for (index = 0U; index < count; index ++)
    if (!cf_v2_ppd_graph_append(buffer, "*cupsFilter: \"%s\"\n", value))
      return 0;
  return 1;
}

static int
cf_v2_ppd_graph_append_opaque(cf_v2_ppd_graph_buffer_t *buffer,
                              const cf_v2_ppd_graph_relation_t *graph)
{
  size_t length = cf_v2_length_relation_value(&graph->opaque_length);
  size_t index;

  if (length > graph->opaque.size)
    length = graph->opaque.size;
  if (graph->opaque_mode == CF_V2_RELATION_EXPLICIT)
    return cf_v2_ppd_graph_append_bytes(buffer, graph->opaque.data, length);
  if (!cf_v2_ppd_graph_append(buffer, "*%% graph-material="))
    return 0;
  for (index = 0U; index < length; index ++)
    if (!cf_v2_ppd_graph_append(buffer, "%02x", graph->opaque.data[index]))
      return 0;
  return cf_v2_ppd_graph_append(buffer, "\n");
}

static int
cf_v2_ppd_graph_build(const cf_v2_ppd_graph_relation_t *graph,
                      cf_v2_ppd_graph_buffer_t *buffer, size_t node_count)
{
  int foomatic = cf_v2_scalar_relation_value(&graph->foomatic) != 0;
  size_t index;

  if (!cf_v2_ppd_graph_append(
          buffer,
          "*PPD-Adobe: \"4.3\"\n"
          "*FormatVersion: \"4.3\"\n"
          "*FileVersion: \"1.0\"\n"
          "*LanguageVersion: English\n"
          "*LanguageEncoding: ISOLatin1\n"
          "*Manufacturer: \"OpenPrinting\"\n"
          "*ModelName: \"Generic graph printer\"\n"
          "*ShortNickName: \"Generic graph\"\n"
          "*NickName: \"Generic graph%s printer\"\n"
          "*PCFileName: \"PPDGRF.PPD\"\n"
          "*Product: \"(Generic graph printer)\"\n"
          "*PSVersion: \"(3010) 0\"\n"
          "*LanguageLevel: \"3\"\n"
          "*ColorDevice: True\n"
          "*cupsVersion: 2.0\n"
          "*cupsFilter: \"image/pwg-raster 0 rastertopwg\"\n"
          "*OpenUI *PageSize/Media Size: PickOne\n"
          "*DefaultPageSize: Letter\n"
          "*PageSize Letter/Letter: \"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
          "*CloseUI: *PageSize\n"
          "*OpenUI *PageRegion/Media Region: PickOne\n"
          "*DefaultPageRegion: Letter\n"
          "*PageRegion Letter/Letter: \"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
          "*CloseUI: *PageRegion\n"
          "*DefaultImageableArea: Letter\n"
          "*ImageableArea Letter: \"18 36 594 756\"\n"
          "*DefaultPaperDimension: Letter\n"
          "*PaperDimension Letter: \"612 792\"\n",
          foomatic ? " Foomatic" : ""))
    return 0;

  for (index = 0U; index < node_count; index ++) {
    const cf_v2_ppd_graph_node_t *node = graph->nodes + index;
    int ok = 1;

    if (!cf_v2_ppd_graph_node_enabled(graph, index))
      continue;
    switch (node->object.kind) {
      case CF_V2_OBJECT_NULL:
        break;
      case CF_V2_OBJECT_SCALAR:
        ok = cf_v2_ppd_graph_append_regular(buffer, graph, node);
        break;
      case CF_V2_OBJECT_DICTIONARY:
        ok = cf_v2_ppd_graph_append_custom(buffer, graph, node);
        break;
      case CF_V2_OBJECT_ARRAY:
        ok = cf_v2_ppd_graph_append_page_custom(buffer, graph, node);
        break;
      case CF_V2_OBJECT_STREAM:
        ok = cf_v2_ppd_graph_append_metadata(buffer, node);
        break;
      case CF_V2_OBJECT_OPAQUE:
        ok = cf_v2_ppd_graph_append_filter(buffer, graph, node);
        break;
      default:
        ok = 0;
        break;
    }
    if (!ok)
      return 0;
  }
  return cf_v2_ppd_graph_append_opaque(buffer, graph) &&
         cf_v2_ppd_graph_append(buffer, "*%% EOF\n");
}

static void
cf_v2_ppd_graph_close(cf_v2_ppd_graph_player_t *player)
{
  if (player->ppd)
    ppdClose(player->ppd);
  player->ppd = NULL;
}

static void
cf_v2_ppd_graph_parse_action(cf_v2_ppd_graph_player_t *player)
{
  cf_v2_ppd_graph_close(player);
  player->ppd = ppdOpenFile(player->path);
  if (player->ppd && !libppd_within_work_budget(player->ppd))
    cf_v2_ppd_graph_close(player);
}

static void
cf_v2_ppd_graph_select_action(cf_v2_ppd_graph_player_t *player,
                              unsigned argument)
{
  size_t index;

  if (!player->ppd)
    return;
  ppdMarkDefaults(player->ppd);
  for (index = 0U; index < player->node_count; index ++) {
    const cf_v2_ppd_graph_node_t *node = player->graph->nodes + index;
    uint32_t reference = cf_v2_ppd_graph_resolved_reference(node);
    char keyword[PPD_MAX_NAME];
    char choice[PPD_MAX_NAME];

    if (!cf_v2_ppd_graph_node_enabled(player->graph, index))
      continue;
    if (node->object.kind == CF_V2_OBJECT_SCALAR) {
      snprintf(keyword, sizeof(keyword), "Option%u", node->object.object_id);
      snprintf(choice, sizeof(choice), "Choice%u", reference + argument % 2U);
      (void)ppdMarkOption(player->ppd, keyword, choice);
    } else if (node->object.kind == CF_V2_OBJECT_ARRAY) {
      (void)ppdMarkOption(player->ppd, "PageSize", "Custom.100x200");
    }
  }
  libppd_mark_semantic_state(player->ppd, player->hash + argument);
}

static void
cf_v2_ppd_graph_emit_action(cf_v2_ppd_graph_player_t *player,
                            unsigned argument)
{
  static const ppd_section_t sections[] = {
    PPD_ORDER_ANY, PPD_ORDER_DOCUMENT, PPD_ORDER_EXIT,
    PPD_ORDER_JCL, PPD_ORDER_PAGE, PPD_ORDER_PROLOG,
  };
  cups_page_header_t header;
  char *output;

  if (!player->ppd)
    return;
  output = ppdEmitString(
      player->ppd,
      sections[argument % (sizeof(sections) / sizeof(sections[0]))], 0.0f);
  free(output);
  if (argument & 1U)
    (void)ppdRasterInterpretPPD(&header, player->ppd, 0, NULL, NULL);
}

static void
cf_v2_ppd_graph_cache_action(cf_v2_ppd_graph_player_t *player,
                             unsigned argument)
{
  ppd_cache_t *cache;

  (void)argument;
  cache = ppdCacheCreateWithPPD(player->ppd);
  ppdCacheDestroy(cache);
}

static void
cf_v2_ppd_graph_attribute_action(cf_v2_ppd_graph_player_t *player,
                                 unsigned argument)
{
  ipp_t *attrs = ppdLoadAttributes(player->ppd);

  (void)argument;
  ippDelete(attrs);
}

static void
cf_v2_ppd_graph_read_action(cf_v2_ppd_graph_player_t *player,
                            unsigned argument)
{
  if (!player->ppd)
    return;
  switch (argument % 4U) {
    case 0U:
      cf_v2_ppd_graph_cache_action(player, argument);
      break;
    case 1U:
      cf_v2_ppd_graph_attribute_action(player, argument);
      break;
    case 2U:
      cf_v2_ppd_graph_cache_action(player, argument);
      if (player->ppd)
        cf_v2_ppd_graph_attribute_action(player, argument);
      break;
    default: {
      cups_array_t *languages;

      (void)ppdLocalize(player->ppd);
      languages = ppdGetLanguages(player->ppd);
      ppdFreeLanguages(languages);
      break;
    }
  }
}

static void
cf_v2_ppd_graph_play(cf_v2_ppd_graph_player_t *player,
                     cf_v2_ppd_graph_relation_t *graph)
{
  size_t count = cf_v2_cardinality_value(&graph->action_count);
  size_t index;

  if (count > CF_V2_PPD_GRAPH_ACTION_BYTES / 2U)
    count = CF_V2_PPD_GRAPH_ACTION_BYTES / 2U;
  cf_v2_ppd_graph_parse_action(player);
  for (index = 0U; index < count; index ++) {
    cf_v2_action_t action;
    unsigned repetition;

    if (!cf_v2_action_program_next(&graph->actions, &action))
      break;
    cf_v2_relation_stats_action(&cf_v2_ppd_graph_stats, action.kind);
    for (repetition = 0U; repetition < action.repetitions; repetition ++) {
      switch (action.kind) {
        case CF_V2_ACTION_PARSE:
          cf_v2_ppd_graph_parse_action(player);
          break;
        case CF_V2_ACTION_SELECT:
          cf_v2_ppd_graph_select_action(player,
                                        action.argument + repetition);
          break;
        case CF_V2_ACTION_EMIT:
          cf_v2_ppd_graph_emit_action(player,
                                      action.argument + repetition);
          break;
        case CF_V2_ACTION_READ:
          cf_v2_ppd_graph_read_action(player,
                                      action.argument + repetition);
          break;
        case CF_V2_ACTION_FINISH:
          cf_v2_ppd_graph_close(player);
          break;
        default:
          break;
      }
    }
  }
  cf_v2_ppd_graph_close(player);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  cf_v2_ppd_graph_relation_t graph;
  uint8_t ppd_text[CF_V2_PPD_GRAPH_TEXT_SIZE];
  cf_v2_ppd_graph_buffer_t buffer = {
    ppd_text, 0U, sizeof(ppd_text),
  };
  cf_v2_ppd_graph_player_t player;
  char path[] = "/tmp/cupsfilters-v2-ppd-graph.XXXXXX";
  size_t node_count;
  int fd;

  if (size > CF_V2_PPD_GRAPH_MAX_INPUT ||
      !cf_v2_ppd_graph_parse(data, size, &graph))
    return 0;
  cf_v2_relation_stats_register(&cf_v2_ppd_graph_stats,
                                cf_v2_ppd_graph_stats_name());
  cf_v2_ppd_graph_record(&cf_v2_ppd_graph_stats, &graph);
  node_count = cf_v2_cardinality_value(&graph.object_count);
  if (node_count > CF_V2_PPD_GRAPH_NODE_COUNT)
    node_count = CF_V2_PPD_GRAPH_NODE_COUNT;
  for (size_t index = 0U; index < node_count; index ++) {
    const cf_v2_ppd_graph_node_t *node = graph.nodes + index;

    if (!cf_v2_ppd_graph_node_enabled(&graph, index))
      continue;
    cf_v2_relation_stats_reference(&cf_v2_ppd_graph_stats,
                                   node->reference_mode);
    cf_v2_relation_stats_object(&cf_v2_ppd_graph_stats,
                                node->object.kind);
    cf_v2_relation_stats_cardinality(&cf_v2_ppd_graph_stats,
                                     node->cardinality.class_id);
  }
  if (!cf_v2_ppd_graph_build(&graph, &buffer, node_count))
    return 0;

  fd = mkstemp(path);
  if (fd < 0)
    return 0;
  if (libppd_write_all(fd, ppd_text, buffer.size)) {
    close(fd);
    unlink(path);
    return 0;
  }
  if (close(fd)) {
    unlink(path);
    return 0;
  }
  memset(&player, 0, sizeof(player));
  player.path = path;
  player.graph = &graph;
  player.node_count = node_count;
  player.hash = libppd_hash(data, size);
  cf_v2_init_runtime();
  cf_v2_ppd_graph_play(&player, &graph);
  unlink(path);
  return 0;
}
