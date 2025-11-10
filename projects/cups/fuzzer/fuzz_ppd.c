/*
 * PPD, Cache and PWG fuzz program for CUPS
 *
 * This harness is a combination of
 * testppd.c, testcache.c and testpwg.c
 * 
 * Licensed under Apache License v2.0.
 * See the file "LICENSE" for more information.
 */

#include "ppd-private.h"
#include "file-private.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
  char *ppdsize;
  char *legacy;
  char *pwg;
  char *ppdmedia;
  char *marked_option;
  char *options_str;
  char **cups_options;
  char **cups_values;
  int elem_counter;
  cups_option_t *options;
  int num_options;
  _ppd_cache_t *pc;
  ipp_t *job;
  ppd_file_t *ppd;
} fuzz_ppd_ctx_t;

static void
cleanup_resources(fuzz_ppd_ctx_t *ctx)
{
  if (!ctx)
    return;

  if (ctx->cups_options)
  {
    for (int i = 0; i < ctx->elem_counter; i++)
      free(ctx->cups_options[i]);
    free(ctx->cups_options);
    ctx->cups_options = NULL;
  }

  if (ctx->cups_values)
  {
    for (int i = 0; i < ctx->elem_counter; i++)
      free(ctx->cups_values[i]);
    free(ctx->cups_values);
    ctx->cups_values = NULL;
  }

  if (ctx->options)
  {
    cupsFreeOptions(ctx->num_options, ctx->options);
    ctx->options = NULL;
    ctx->num_options = 0;
  }

  if (ctx->pc)
  {
    _ppdCacheDestroy(ctx->pc);
    ctx->pc = NULL;
  }

  if (ctx->job)
  {
    ippDelete(ctx->job);
    ctx->job = NULL;
  }

  if (ctx->ppd)
  {
    ppdClose(ctx->ppd);
    ctx->ppd = NULL;
  }

  free(ctx->ppdsize);
  ctx->ppdsize = NULL;
  free(ctx->legacy);
  ctx->legacy = NULL;
  free(ctx->pwg);
  ctx->pwg = NULL;
  free(ctx->ppdmedia);
  ctx->ppdmedia = NULL;
  free(ctx->marked_option);
  ctx->marked_option = NULL;
  free(ctx->options_str);
  ctx->options_str = NULL;
}

int fuzz_ppd(char *string, int len, char *filename, char *pwgname);
void unlink_tempfile(void);

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  /*
   * We need a huge input, because it should contain
   * options and ppd file
   */
  if (Size < 1000)
    return 1;

  atexit(unlink_tempfile);

  char *filename = (char *)malloc(sizeof(char) * 256);
  char *pwgname = (char *)malloc(sizeof(char) * 256);
  if (!filename || !pwgname)
  {
    free(filename);
    free(pwgname);
    return 1;
  }

  sprintf(filename, "/tmp/fuzz_ppd.%d.ppd", getpid());
  sprintf(pwgname, "/tmp/fuzz_ppd.%d.pwg", getpid());

  char *string = (char *)calloc(sizeof(char), Size + 1);
  if (!string)
  {
    free(filename);
    free(pwgname);
    return 1;
  }
  memcpy(string, Data, Size);
  int len = Size;

  fuzz_ppd(string, len, filename, pwgname);

  unlink_tempfile();
  free(filename);
  free(pwgname);
  free(string);
  return 0;
}

static int
consume_string(char **dest, char **data, int *len)
{
  *dest = strdup(*data);
  if (!*dest)
    return -1;

  int consumed = (int)strlen(*dest) + 1;
  *len -= consumed;
  if (*len <= 0)
    return -1;

  *data += consumed;
  return 0;
}

int fuzz_ppd(char *data, int len, char *filename, char *pwgname)
{
  fuzz_ppd_ctx_t ctx = {0};
  int ret = 0;
  int finishings[1024];
  int width;
  int length;
  ppd_choice_t *ppd_bin;
  ppd_size_t minsize, maxsize;
  cups_page_header2_t header;

  do
  {
    if (consume_string(&ctx.ppdsize, &data, &len))
    {
      ret = 1;
      break;
    }
    if (consume_string(&ctx.legacy, &data, &len))
    {
      ret = 1;
      break;
    }
    if (consume_string(&ctx.pwg, &data, &len))
    {
      ret = 1;
      break;
    }
    if (consume_string(&ctx.ppdmedia, &data, &len))
    {
      ret = 1;
      break;
    }
    if (consume_string(&ctx.marked_option, &data, &len))
    {
      ret = 1;
      break;
    }
    if (consume_string(&ctx.options_str, &data, &len))
    {
      ret = 1;
      break;
    }

    char buf[12] = {0};
    if (!strncpy(buf, data, 11))
    {
      ret = 1;
      break;
    }
    length = atoi(buf);
    data += strlen(buf);
    len -= strlen(buf);

    if (!strncpy(buf, data, 11))
    {
      ret = 1;
      break;
    }
    width = atoi(buf);
    data += strlen(buf);
    len -= strlen(buf);

    ctx.cups_options = (char **)malloc(sizeof(char *) * 2);
    ctx.cups_values = (char **)malloc(sizeof(char *) * 2);
    if (!ctx.cups_options || !ctx.cups_values)
    {
      ret = 1;
      break;
    }

    ctx.elem_counter = 0;
    int counter = 0;
    size_t options_len = strlen(ctx.options_str);
    for (size_t i = 0; i < options_len; i++)
    {
      ctx.cups_options[ctx.elem_counter] = (char *)malloc(sizeof(char));
      ctx.cups_values[ctx.elem_counter] = (char *)malloc(sizeof(char));
      if (!ctx.cups_options[ctx.elem_counter] || !ctx.cups_values[ctx.elem_counter])
      {
        ret = 1;
        break;
      }

      ctx.cups_options[ctx.elem_counter][0] = '\0';
      ctx.cups_values[ctx.elem_counter][0] = '\0';

      if (!ctx.options_str[i])
        break;

      counter = 0;
      while(ctx.options_str[i] != '=' && ctx.options_str[i] && ctx.options_str[i] != ' ')
      {
        char *tmp = (char *)realloc(ctx.cups_options[ctx.elem_counter], sizeof(char) * (counter + 2));
        if (!tmp)
        {
          ret = 1;
          break;
        }
        ctx.cups_options[ctx.elem_counter] = tmp;
        ctx.cups_options[ctx.elem_counter][counter] = ctx.options_str[i];
        counter++;
        i++;
      }
      if (ret)
        break;

      ctx.cups_options[ctx.elem_counter][counter] = '\0';
      if (ctx.options_str[i] == '=')
      {
        ++i;
        counter = 0;
        while(ctx.options_str[i] != ' ' && ctx.options_str[i])
        {
          char *tmp = (char *)realloc(ctx.cups_values[ctx.elem_counter], sizeof(char) * (counter + 2));
          if (!tmp)
          {
            ret = 1;
            break;
          }
          ctx.cups_values[ctx.elem_counter] = tmp;
          ctx.cups_values[ctx.elem_counter][counter] = ctx.options_str[i];
          counter++;
          i++;
        }
        if (ret)
          break;
        ctx.cups_values[ctx.elem_counter][counter] = '\0';
      }

      ctx.elem_counter++;
      char **new_options = (char **)realloc(ctx.cups_options, sizeof(char *) * (ctx.elem_counter + 1));
      char **new_values = (char **)realloc(ctx.cups_values, sizeof(char *) * (ctx.elem_counter + 1));
      if (!new_options || !new_values)
      {
        free(new_options);
        free(new_values);
        ret = 1;
        break;
      }
      ctx.cups_options = new_options;
      ctx.cups_values = new_values;
    }

    if (ret || len <= 0)
    {
      ret = 1;
      break;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
      ret = 1;
      break;
    }

    size_t written = fwrite(data, sizeof(*data), len, fp);
    fclose(fp);
    if ((int)written != len)
    {
      ret = 1;
      break;
    }

    ctx.ppd = ppdOpenFile(filename);
    if (!ctx.ppd)
    {
      ppd_status_t err;
      int line;
      err = ppdLastError(&line);
      ppdErrorString(err);
      ret = 1;
      break;
    }

    ctx.pc = _ppdCacheCreateWithPPD(NULL, ctx.ppd);
    if (!ctx.pc)
    {
      ret = 1;
      break;
    }

    char *pagesize;
    _ppdCacheWriteFile(ctx.pc, pwgname, NULL);
    _ppd_cache_t *pc2 = _ppdCacheCreateWithFile(pwgname, NULL);
    if (pc2)
      _ppdCacheDestroy(pc2);
    ppdPageSize(ctx.ppd, ctx.ppdsize);
    pagesize = _ppdCacheGetPageSize(ctx.pc, NULL, ctx.ppdsize, NULL);
    (void)pagesize;

    ctx.job = ippNew();
    if (ctx.job)
    {
      ippDelete(ctx.job);
      ctx.job = NULL;
    }

    pwgMediaForPWG(ctx.pwg);
    pwgMediaForLegacy(ctx.legacy);
    pwgMediaForPPD(ctx.ppdmedia);
    pwgMediaForSize(width, length);

    ctx.num_options = cupsParseOptions(ctx.options_str, 0, &ctx.options);
    ppdMarkDefaults(ctx.ppd);
    cupsMarkOptions(ctx.ppd, ctx.num_options, ctx.options);
    ppdConflicts(ctx.ppd);

    _ppdCacheGetFinishingValues(ctx.ppd, ctx.pc, (int)sizeof(finishings) / sizeof(finishings[0]), finishings);
    cupsRasterInterpretPPD(&header, ctx.ppd, ctx.num_options, ctx.options, NULL);

    if (strlen(ctx.marked_option) > 0)
    {
      char *choice = (char *)calloc(1, sizeof(char));
      if (!choice)
      {
        ret = 1;
        break;
      }

      for (int i = 0; i < (int)strlen(ctx.marked_option); i++)
      {
        if (!ctx.marked_option[i] || ctx.marked_option[i] != ' ')
        {
          char *tmp = (char *)realloc(choice, sizeof(char) * (i + 2));
          if (!tmp)
          {
            free(choice);
            ret = 1;
            break;
          }
          choice = tmp;
          choice[i] = ctx.marked_option[i];
          choice[i + 1] = '\0';
        }
        else
          break;
      }
      if (ret)
        break;

      ppdFindAttr(ctx.ppd, choice, ctx.marked_option + strlen(choice));
      ppdFindNextAttr(ctx.ppd, choice, NULL);
      if ((ppd_bin = ppdFindMarkedChoice(ctx.ppd, choice)) != NULL)
        _ppdCacheGetBin(ctx.pc, ppd_bin->choice);
      char buffer[1024] = {0};
      ppdLocalizeIPPReason(ctx.ppd, choice, ctx.marked_option + strlen(choice), buffer, sizeof(buffer));
      for (int i = 0; i < ctx.elem_counter; i++)
      {
        ppdMarkOption(ctx.ppd, ctx.cups_options[i], ctx.cups_values[i]);
        cupsGetOption(ctx.cups_options[i], ctx.num_options, ctx.options);
        ctx.num_options = cupsGetConflicts(ctx.ppd, ctx.cups_options[i], ctx.cups_values[i], &ctx.options);
        cupsResolveConflicts(ctx.ppd, ctx.cups_options[i], ctx.cups_values[i], &ctx.num_options, &ctx.options);
        ppdInstallableConflict(ctx.ppd, ctx.cups_options[i], ctx.cups_values[i]);
      }
      ppdInstallableConflict(ctx.ppd, ctx.options_str, choice);
      ppdLocalizeMarkerName(ctx.ppd, choice);
      free(choice);
    }

    for (int i = 0; i < 5; i++)
      ppdEmitString(ctx.ppd, i, 0.0);

    ppdPageSizeLimits(ctx.ppd, &minsize, &maxsize);
    ppdPageSize(ctx.ppd, NULL);

  } while (0);

  cleanup_resources(&ctx);
  return ret;
}

void unlink_tempfile(void)
{
  char filename[256];
  sprintf(filename, "/tmp/fuzz_ppd.%d.ppd", getpid());
  unlink(filename);
  sprintf(filename, "/tmp/fuzz_ppd.%d.pwg", getpid());
  unlink(filename);
  sprintf(filename, "%s.N", filename);
  unlink(filename);
}
