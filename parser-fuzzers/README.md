# cups-filters libFuzzer harnesses

This directory owns the libFuzzer and OSS-Fuzz integration for the current
OpenPrinting split stack: CUPS, PDFio, libcupsfilters, libppd, and cups-filters.
It exports 25 continuous targets and preserves the existing raw-PDF target name
`fuzz_pdf` so OSS-Fuzz can retain its accumulated corpus identity.

## Design

The deploy set follows one ownership rule:

```text
one implementation + one coherent input language + one production API lifecycle
= one OSS-Fuzz target
```

- Raw lanes retain malformed file-header and syntax exploration where arbitrary
  bytes are useful.
- Structured lanes encode related page geometry, raster layout, PDF object
  references, PPD records, job options, and output state as typed controls.
- Custom mutators and crossovers preserve required framing and relationships
  while continuing to mutate values and switch routes.
- Finite printer profiles replace unconstrained PPD generation with valid,
  diverse capability sets.
- Output oracles reopen PDF, raster, or PostScript output and check semantic
  invariants in addition to sanitizer failures.
- Every deploy target runs one input in-process. The harnesses do not launch
  standalone filters, Ghostscript, or other renderer processes.

Shared source blocks are linked into multiple binaries at build time. OSS-Fuzz
still executes each target and maintains each corpus independently.

## Target set

| Area | OSS-Fuzz binaries | Input and lifecycle focus |
| --- | --- | --- |
| Job and control | `fuzz_cupsfilters_banner_to_pdf`, `fuzz_cupsfilters_command_to_escpx`, `fuzz_cupsfilters_command_to_pclx`, `fuzz_cupsfilters_foomatic_jcl` | Banner objects, command grammar and dispatch, JCL parsing and merge state |
| Image decoders | `fuzz_cupsfilters_image_jpeg_decoder`, `fuzz_cupsfilters_image_png_decoder`, `fuzz_cupsfilters_image_tiff_decoder` | Bounded raw codec input and image-row decoding |
| Image filters | `fuzz_cupsfilters_image_to_pdf`, `fuzz_cupsfilters_image_to_raster`, `fuzz_cupsfilters_image_to_ps` | Image layout, color conversion, page generation, and output validation |
| PDF and PCLm | `fuzz_pdf`, `fuzz_cupsfilters_pdf_to_pdf_graph`, `fuzz_cupsfilters_pclm_graph` | Raw PDF compatibility, typed PDF object graphs, PCLm page/image relations |
| PPD | `fuzz_cupsfilters_ppd_semantic`, `fuzz_cupsfilters_ppd_cache_ipp`, `fuzz_cupsfilters_ppd_profile` | PPD grammar, cache/IPP conversion, profile and option semantics |
| PostScript | `fuzz_cupsfilters_ps_to_ps` | DSC parsing, page selection, and sequence state |
| PWG input | `fuzz_cupsfilters_pwg_to_pdf`, `fuzz_cupsfilters_pwg_to_raster` | PWG raster headers, scaling, color order, and page output |
| Raster output | `fuzz_cupsfilters_raster_to_hp`, `fuzz_cupsfilters_raster_to_escpx_state`, `fuzz_cupsfilters_raster_to_pclx_state`, `fuzz_cupsfilters_raster_to_ps`, `fuzz_cupsfilters_raster_to_pwg` | Raster layout, compression, printer state, and output framing |
| Text | `fuzz_cupsfilters_text_to_pdf`, `fuzz_cupsfilters_text_to_text` | Encoding, line/page layout, selection, and generated output |

The canonical names and ownership mapping are in `manifests/target-map.tsv`.
Names beginning with `fuzz_v3_` are private implementation identifiers only;
they are never exported as OSS-Fuzz binary names.

## Layout

| Path | Purpose |
| --- | --- |
| `oss_fuzz_build.sh` | Builds the split stack with OSS-Fuzz compiler, sanitizer, and libFuzzer flags |
| `harnesses/` | Exact 219-file source/include dependency closure used by deploy targets |
| `corpus/` | One startup corpus archive per exported binary |
| `dictionaries/` | One libFuzzer dictionary per exported binary |
| `config/` | Fontconfig runtime configuration and the narrow UBSan ignorelist |
| `manifests/` | Deploy names, compatibility identity, source closure, and target mapping |
| `tests/` | Standard-library-only package integrity tests |

The internal `harnesses/libfuzzer/v2` directory contains shared structured-input
and oracle blocks reused by the converged implementations. It is a dependency
closure, not a second exported target registry.

## Validation

Run the repository-level package checks with:

```bash
make -C parser-fuzzers check
```

The OSS-Fuzz build entry point is
`projects/cups-filters/oss_fuzz_build.sh`. From a Google OSS-Fuzz checkout with
the companion cups-filters project configuration applied, run:

```bash
python3 infra/helper.py build_image cups-filters
python3 infra/helper.py build_fuzzers --sanitizer address cups-filters
python3 infra/helper.py check_build --sanitizer address cups-filters
python3 infra/helper.py build_fuzzers --sanitizer undefined cups-filters
python3 infra/helper.py check_build --sanitizer undefined cups-filters
```

An individual target from the AddressSanitizer build can then be started with:

```bash
python3 infra/helper.py run_fuzzer cups-filters \
  fuzz_cupsfilters_pdf_to_pdf_graph
```

The package has been qualified on Ubuntu 24.04 with libFuzzer under
AddressSanitizer/LeakSanitizer and UndefinedBehaviorSanitizer. All 26 binaries
pass OSS-Fuzz `check_build` and startup-corpus replay. The 25 continuous targets
also completed one-hour single-process ASan/LSan stability runs before
publication.

The repository is licensed under Apache-2.0. Corpus provenance and licensing
are documented in `corpus/README.md`.
