// PDF-parsing fuzzer for cups-filters' pdftopdf filter.
//
// Unlike the previous harness (which only drove the pdfOut *writer* with the
// input as an opaque content stream), this feeds the fuzz bytes to the real
// qpdf-backed PDFTOPDF_Processor: it parses the PDF (qpdf processFile), walks
// the page tree, reads page geometry, and checks permissions / AcroForm — i.e.
// it actually exercises PDF parsing.

#include "pdftopdf_processor.h"

#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

// Silence stdout (qpdf / the processor may print) but keep stderr intact so
// libFuzzer progress and ASAN crash reports are preserved; restore afterwards.
static int silence_stdout() {
  fflush(stdout);
  int saved = dup(STDOUT_FILENO);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }
  return saved;
}

static void restore_stdout(int saved) {
  if (saved < 0)
    return;
  fflush(stdout);
  dup2(saved, STDOUT_FILENO);
  close(saved);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 5)
    return 0;

  int saved_stdout = silence_stdout();

  FILE *f = fmemopen(const_cast<uint8_t *>(Data), Size, "rb");
  if (f) {
    std::unique_ptr<PDFTOPDF_Processor> proc(PDFTOPDF_Factory::processor());
    try {
      // loadFile parses the PDF via qpdf (returns false on malformed input).
      if (proc && proc->loadFile(f, WillStayAlive, 1)) {
        proc->check_print_permissions();
        proc->hasAcroForm();
        std::vector<std::shared_ptr<PDFTOPDF_PageHandle>> pages =
            proc->get_pages();
        for (const std::shared_ptr<PDFTOPDF_PageHandle> &p : pages) {
          if (p)
            (void)p->getRect(); // parses /MediaBox etc.
        }
      }
    } catch (...) {
      // qpdf / pdftopdf throw on malformed PDFs; that is expected, not a bug.
    }
    fclose(f);
  }

  restore_stdout(saved_stdout);
  return 0;
}
