# GSoC 2026 Final Report: Advanced System-Level Fuzzing for OpenPrinting

| Field | Value |
| --- | --- |
| Contributor | Yibo Tan (Aiden Kim) |
| Mentoring organization | The Linux Foundation (OpenPrinting) |
| Project | Advanced System-Level Fuzzing for OpenPrinting: Deep State Exploration and LLM-Augmented Mutation |
| Program | Google Summer of Code 2026 |
| Original project idea | [System-Level Fuzzing for Parsing Features in OpenPrinting Projects](https://openprinting.github.io/gsoc/2026/System-Level-Fuzzing-for-Parsing-Features-in-OpenPrinting-Projects) |
| Accepted proposal summary | [OpenPrinting GSoC 2026 contributor announcement](https://openprinting.github.io/OpenPrinting-News-Google-Summer-of-Code-2026-All-contributors-did-a-great-start) |
| Upstream OpenPrinting contribution | Pull request pending |
| OSS-Fuzz integration | Pull request pending after upstream harness review |

## Project Overview

This project built an in-process libFuzzer and OSS-Fuzz architecture for the
current OpenPrinting printing stack from the ground up. The target stack is
split across CUPS, PDFio, libcupsfilters, libppd, and cups-filters. At the
start of the project, it did not have a complete set of sustainably deployable
fuzz targets for its parser and filter families.

Printing filters are controlled by more than document bytes. Their behavior
also depends on PPD data, IPP attributes, job options, page geometry, Raster
layout, color spaces, and document object graphs. The project therefore
focused on modeling coherent production API lifecycles instead of merely
wrapping command-line filter binaries.

The resulting work product contains 25 new continuous fuzz targets, preserves
the existing `fuzz_pdf` corpus identity, and provides the build, corpus,
dictionary, mutation, output-validation, and resource-management support
needed for OSS-Fuzz deployment.

## Original Proposal and Scope Refinement

The accepted proposal described the central objective as follows:

> This project aims to transition OpenPrinting's security infrastructure from
> fragmented unit-testing to a comprehensive, state-aware system fuzzing
> framework.

The proposed work focused on system-level media paths, authentic API sequences,
structured recombination, high-quality seed corpora, coverage expansion, and
responsible bug discovery. It considered AFL++, Honggfuzz, and OSS-Fuzz-Gen as
possible exploration tools.

During implementation, the production deliverable converged on libFuzzer and
OSS-Fuzz. This provides in-process coverage, sanitizer integration, persistent
corpus management, and a clear upstream deployment path. LLM-assisted analysis
was used as an engineering aid during parser modeling and review; the delivered
fuzzers themselves are native binaries with no model or network dependency.

| Proposal direction | Final implementation |
| --- | --- |
| System-level media and filter paths | In-process production filter and library lifecycles |
| API-sequence-based harnesses | Lifecycle adapters that initialize document, job, PPD/IPP, and output state |
| Structured or IR-based recombination | Typed shared blocks, custom mutators, and crossovers |
| Curated seed corpus | Per-target startup corpora and dictionaries covering format and state modes |
| Coverage expansion | Complementary raw and structured lanes with measured coverage and resource use |
| Bug discovery and fixing | Upstream reproduction and public issue reporting |

This refinement changed the deployable mechanism, not the proposal's core goal:
reaching deep, realistic parsing states and delivering a reusable fuzzing setup
for the OpenPrinting media-processing stack.

## Goals

The project had five main goals:

1. Call cups-filters and supporting library APIs directly from libFuzzer,
   without launching standalone filter processes or external interpreters.
2. Cover the principal PDF, image, Raster, printer-language, PPD, PostScript,
   command, banner, and text processing families.
3. Preserve printing-specific relationships that ordinary byte mutation is
   unlikely to construct or maintain.
4. Validate generated output in addition to relying on sanitizer-detected
   crashes.
5. Package a stable, resource-bounded target set for the OSS-Fuzz environment.

All implementation and local qualification work defined by this scope is
complete.

## Work Completed

### In-process production paths

Every exported binary exposes `LLVMFuzzerTestOneInput` and enters a real
filter or library API in process. Harness adapters initialize the input
stream, filter context, PPD or printer profile, IPP attributes, job options,
and output destination required by that lifecycle.

The deploy set does not shell out to `cupsfilter`, standalone filter
executables, Ghostscript, MuPDF, or another renderer. This keeps coverage and
sanitizer failures attributable to the code being tested and avoids process
startup on every test case.

### Target convergence

Targets were converged according to one rule:

```text
one implementation + one coherent input language + one production API lifecycle
= one deploy target
```

This avoids creating a separate corpus for every option or internal function.
One target may exercise several related routes when they share a meaningful
input language and lifecycle. A separate target is retained when raw syntax,
structured state, or ownership behavior is materially different.

The final set covers:

| Family | Main state explored |
| --- | --- |
| Job control | Banner templates, CUPS command parsing, dispatch, and Foomatic JCL |
| Image decoding | Bounded JPEG, PNG, and TIFF decode lifecycles |
| Image filters | Scaling, color conversion, page layout, and PDF/Raster/PostScript output |
| PDF and PCLm | Raw PDF syntax, object graphs, references, streams, and page relations |
| PPD and IPP | PPD grammar, profiles, options, cache state, and IPP conversion |
| PostScript | DSC parsing, page selection, sequence state, and output rewriting |
| PWG and CUPS Raster | Headers, dimensions, row layout, color order, scaling, and page state |
| Printer languages | PCL, ESC/P, compression, plane layout, banding, and output framing |
| Text | Encoding, wrapping, pagination, selection, and generated output |

The canonical continuous target set and retained compatibility identity are
recorded in the [deploy manifest](../../parser-fuzzers/manifests/deploy-targets.txt)
and [compatibility manifest](../../parser-fuzzers/manifests/compatibility-targets.txt).

### Raw and structured exploration

Raw lanes retain arbitrary byte mutation where malformed headers, truncated
syntax, invalid tokens, and parser rejection boundaries are the state of
interest. Structured lanes are used where reaching deeper processing requires
several related values to remain valid at the same time.

Reusable typed blocks model relationships such as:

- page dimensions, resolution, margins, and orientation;
- Raster color order, bit depth, bytes per line, row count, and compression;
- PDF and PCLm object references, stream lengths, and page relationships;
- PPD records, IPP attributes, and job-option combinations;
- text encoding, line layout, wrapping, pagination, and page selection.

Custom mutators and crossovers preserve framing and these required
relationships while continuing to vary boundary values, modes, and routes.
The shared blocks are source-level components linked into multiple fuzz
binaries; OSS-Fuzz still executes every target and maintains every corpus
independently.

### Semantic output oracles

Selected targets inspect or reopen their PDF, Raster, PostScript, PCL, ESC/P,
or text output. The checks cover page structure, dimensions, row layout,
object relationships, output framing, and other format invariants. This adds
an observable failure signal for output corruption that may not immediately
produce a memory-safety crash.

### Persistent-process resource safety

OSS-Fuzz workers execute many inputs in one process. The harness layer
therefore closes or releases temporary files, file descriptors, PPDs, option
arrays, PDFio objects, image streams, Fontconfig state, and output buffers
after each input. Target-specific maximum input lengths, timeouts, and RSS
limits bound expensive states without changing upstream filter code.

### Corpora and dictionaries

Each exported binary has a startup corpus and libFuzzer dictionary. The clean
package currently contains the following assets, counted directly from the
manifests, archives, and dictionary files in this repository:

| Asset | Count |
| --- | ---: |
| Continuous targets | 25 |
| Compatibility targets | 1 |
| Seed-corpus archives | 26 |
| Corpus entries | 5,369 |
| Dictionaries | 26 |
| Dictionary tokens | 1,698 |

The corpora cover format, route, color, geometry, option, and layout modes.
The dictionaries provide relevant magic values, parser keywords, operators,
commands, and option names.

## Deliverables

The public work product includes:

- 25 new continuously deployable libFuzzer targets;
- the existing raw-PDF target identity `fuzz_pdf`, retained for OSS-Fuzz
  corpus continuity;
- structured input schemas, shared typed blocks, custom mutators, and
  crossovers;
- semantic output oracles for document, Raster, printer-language, and text
  processing;
- one startup corpus, dictionary, and target-specific options file per binary;
- an OSS-Fuzz build for CUPS, PDFio, libcupsfilters, libppd, and cups-filters;
- stable version-free external target names and an explicit target manifest;
- package-integrity tests covering names, source closure, assets, licensing,
  and build entry points;
- upstream reproduction and tracking of 46 public finding reports across five
  affected repositories.

External interpreter-heavy filters are intentionally outside the default
deployment set. Their execution and failure attribution require a different
process-isolation model and are outside the agreed cups-filters-owned scope of
this project.

## Validation and Results

The final package was qualified using an Ubuntu 24.04 OSS-Fuzz builder and
runner. AddressSanitizer/LeakSanitizer and UndefinedBehaviorSanitizer builds
were tested separately. The measurements below were produced from the binaries
and packaged corpora in this submitted tree. The tables use only the public
target-family names defined in this report.

| Qualification | Result |
| --- | ---: |
| Exported binaries | 26 |
| ASan build, OSS-Fuzz check, and startup-corpus replay | 26/26 passed |
| UBSan build, OSS-Fuzz check, and startup-corpus replay | 26/26 passed |
| One-hour ASan/LSan single-process soak | 25/25 passed |
| Total soak executions | 158,696,131 |
| Soak sanitizer or resource artifacts | 0 |
| Seed-corpus function coverage | 58.84% |
| Seed-corpus line coverage | 47.39% |
| Seed-corpus branch coverage | 38.14% |

The final one-hour matrix reported stable file-descriptor use and no crash,
leak, OOM, timeout, slow unit, or other generated artifact across the deploy
set.

### Equal-budget raw and structured comparison

An A/B run compared direct byte mutation with the specialized structured suite
for the same parser family. Each side received one CPU and approximately two
hours of active fuzzing time; the specialized targets shared their CPU in fixed
quanta rather than receiving one CPU per target.

| Family | Lane | Executions | Project functions | Project edges | Peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| PDF | Raw | 2,583,689 | 161/355 (45.4%) | 1,359/4,048 (33.6%) | 862 MiB |
| PDF | Structured | 10,879,222 | 178/355 (50.1%) | 1,344/4,048 (33.2%) | 647 MiB |
| PCLm | Raw | 830,175 | 69/357 (19.3%) | 582/3,686 (15.8%) | 970 MiB |
| PCLm | Structured | 12,719,658 | 91/357 (25.5%) | 760/3,686 (20.6%) | 501 MiB |

Under the same resource budget, the structured suite executed 4.21 times as
many PDF cases and 15.32 times as many PCLm cases. It also reached more project
functions and substantially improved PCLm edge coverage while using less peak
memory. The raw lanes remained complementary: raw PDF held a small edge-count
lead, and raw PCLm uniquely exercised malformed-document repair paths. The
deployment therefore retains both raw syntax exploration and structured state
exploration instead of treating either as a complete replacement.

This was a two-hour engineering comparison, not a statistical time-to-failure
study. Its purpose was to validate the resource model and measure the coverage
and throughput trade-off under equal scheduling.

### Upstream issue reporting

Fuzzing results and targeted code review were independently reproduced against
unmodified upstream code through production processing paths before reporting.
The work submitted, or matched to an existing upstream record, 46 public
finding reports across five repositories:

| Repository | Public reports | Issue references |
| --- | ---: | --- |
| OpenPrinting/cups | 1 | [#1658](https://github.com/OpenPrinting/cups/issues/1658) |
| OpenPrinting/cups-filters | 10 | [#709](https://github.com/OpenPrinting/cups-filters/issues/709) through [#718](https://github.com/OpenPrinting/cups-filters/issues/718) |
| OpenPrinting/libcupsfilters | 27 | [#172](https://github.com/OpenPrinting/libcupsfilters/issues/172) through [#198](https://github.com/OpenPrinting/libcupsfilters/issues/198) |
| OpenPrinting/libppd | 6 | [#81](https://github.com/OpenPrinting/libppd/issues/81) through [#86](https://github.com/OpenPrinting/libppd/issues/86) |
| michaelrsweet/pdfio | 2 | [#177](https://github.com/michaelrsweet/pdfio/issues/177) and [#178](https://github.com/michaelrsweet/pdfio/issues/178) |
| **Total** | **46** | |

The reports cover memory-safety defects, integer and layout boundary errors,
resource-lifetime faults, information disclosure, denial-of-service conditions,
and correctness failures. This count represents submitted or matched reports,
not 46 confirmed security vulnerabilities or CVEs; severity, root-cause status,
and resolution are determined in the linked upstream trackers.

Only public tracker records are counted here. Security-sensitive inputs and any
finding still under coordinated disclosure are intentionally outside this
public report and work-product repository.

The clean package can also validate its source and assets without an OSS-Fuzz
checkout:

```bash
make -C parser-fuzzers check
```

After applying the companion OSS-Fuzz project configuration, the standard
integration flow is:

```bash
python3 infra/helper.py build_image cups-filters
python3 infra/helper.py build_fuzzers --sanitizer address cups-filters
python3 infra/helper.py check_build --sanitizer address cups-filters
python3 infra/helper.py build_fuzzers --sanitizer undefined cups-filters
python3 infra/helper.py check_build --sanitizer undefined cups-filters
```

## Code and Documentation

| Content | Location |
| --- | --- |
| Architecture, target families, and local validation | [`parser-fuzzers/README.md`](../../parser-fuzzers/README.md) |
| OSS-Fuzz build implementation | [`parser-fuzzers/oss_fuzz_build.sh`](../../parser-fuzzers/oss_fuzz_build.sh) |
| OSS-Fuzz project entry point | [`projects/cups-filters/oss_fuzz_build.sh`](../../projects/cups-filters/oss_fuzz_build.sh) |
| Stable continuous target set | [`parser-fuzzers/manifests/deploy-targets.txt`](../../parser-fuzzers/manifests/deploy-targets.txt) |
| Retained compatibility identity | [`parser-fuzzers/manifests/compatibility-targets.txt`](../../parser-fuzzers/manifests/compatibility-targets.txt) |
| Exact deploy source closure | [`parser-fuzzers/manifests/deploy-source-files.txt`](../../parser-fuzzers/manifests/deploy-source-files.txt) |
| Package integrity tests | [`parser-fuzzers/tests/test_package.py`](../../parser-fuzzers/tests/test_package.py) |
| Corpus provenance | [`parser-fuzzers/corpus/README.md`](../../parser-fuzzers/corpus/README.md) |

## Current Status and Upstream Integration

The implementation and qualification defined by the GSoC scope are complete.
The code is prepared as the upstream-owned cups-filters fuzzing integration in
OpenPrinting's `fuzzing` repository.

At the time of this draft:

| Integration step | Status |
| --- | --- |
| OpenPrinting/fuzzing contribution | Prepared in this repository; pull request pending |
| Google OSS-Fuzz project update | Pending upstream review and pull request |
| Production OSS-Fuzz scheduling | Begins after maintainer review and merge |

The implementation inside the agreed scope is complete. Public pull-request
submission and final work-product linking are still required to complete the
GSoC handoff, followed by maintainer review and production adoption. The
OSS-Fuzz-side change must update the existing cups-filters project from its
legacy 1.x build to Ubuntu 24.04 and clone the five current split-stack
repositories before delegating to the upstream-owned build script.

The pending entries will be replaced with permanent pull-request and commit
links as they become available.

## Challenges and Lessons Learned

### Model the full input contract

A document alone is not the complete input to a printing filter. PPD, IPP,
job options, geometry, color state, and output route often determine whether
deep code is reachable. Modeling that contract produced more useful targets
than adding byte-oriented wrappers around every executable.

### Preserve complementary search spaces

Raw mutation remains valuable for syntax and format boundaries, while
structured mutation is needed for multi-field and object-graph state. Neither
approach replaces the other; keeping both gives the fuzzer breadth and depth.

### Treat output as a testable result

Successful return is not enough for a conversion pipeline. Reopening or
independently checking output exposes structural and semantic errors that
sanitizers alone do not identify.

### Persistent execution changes ownership requirements

Filter programs normally exit after one job, but a fuzzing worker does not.
Explicit cleanup and resource observation were necessary to distinguish
harness lifecycle defects from project defects and to make long-running
deployment practical.

### Converge targets around useful corpus identities

Too many narrowly overlapping targets fragment CPU time and corpus feedback.
Converging around coherent input languages and API lifecycles produced a
smaller set whose corpora can continue to accumulate useful state in OSS-Fuzz.

## Acknowledgements

Thanks to mentors Till Kamppeter, Jiongchi Yu, George-Andrei Iosif, and Zixuan
Liu for their guidance and review. Thanks also to the OpenPrinting community
and the OSS-Fuzz maintainers for the projects, documentation, review process,
and infrastructure on which this work is built.
