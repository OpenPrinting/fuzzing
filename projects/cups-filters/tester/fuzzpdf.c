#include "pdfutils.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

static void redirect_stdout_stderr(); // hide stdout

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size < 5) {
    return 0;
  }

  redirect_stdout_stderr();

  pdfOut *pdf;

  pdf=pdfOut_new();
  assert(pdf);

  pdfOut_begin_pdf(pdf);

  // bad font
  int font_obj=pdfOut_add_xref(pdf);
  pdfOut_printf(pdf,"%d 0 obj\n"
                    "<</Type/Font\n"
                    "  /Subtype /Type1\n"
                    "  /BaseFont /%s\n"
                    ">>\n"
                    "endobj\n"
                    ,font_obj,"Courier");
  // test
  const int PageWidth=595,PageLength=842;
  int cobj=pdfOut_add_xref(pdf);

  char *buf = (char *)malloc(Size + 1);
  if (!buf) return 0;
  memcpy(buf, Data, Size);
  buf[Size] = '\0';

  pdfOut_printf(pdf,"%d 0 obj\n"
                    "<</Length %d\n"
                    ">>\n"
                    "stream\n"
                    "%s\n"
                    "endstream\n"
                    "endobj\n"
                    ,cobj, (int) strlen(buf), buf);

  int obj=pdfOut_add_xref(pdf);
  pdfOut_printf(pdf,"%d 0 obj\n"
                    "<</Type/Page\n"
                    "  /Parent 1 0 R\n"
                    "  /MediaBox [0 0 %d %d]\n"
                    "  /Contents %d 0 R\n"
                    "  /Resources << /Font << /a %d 0 R >> >>\n"
                    ">>\n"
                    "endobj\n"
                    ,obj,PageWidth,PageLength,cobj,font_obj);
  pdfOut_add_page(pdf,obj);
  pdfOut_finish_pdf(pdf);

  pdfOut_free(pdf);
  free(buf);

  return 0;
}


void redirect_stdout_stderr() {
    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null < 0) {
        perror("Failed to open /dev/null");
        return;
    }
    dup2(dev_null, STDOUT_FILENO);
    dup2(dev_null, STDERR_FILENO);
    close(dev_null);
}