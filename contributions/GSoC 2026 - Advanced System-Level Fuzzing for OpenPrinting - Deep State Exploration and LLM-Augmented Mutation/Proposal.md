# Advanced System-Level Fuzzing for OpenPrinting: Deep State Exploration and LLM-Augmented Mutation

Program: Google Summer of Code 2026

Type: Proposal

Status: Draft

## Goal

Build a system-level fuzzing workflow for OpenPrinting components that explores
deep parser and filter states across CUPS, cups-filters, libcupsfilters, and
related print-processing paths.

## Current Snapshot

The included `smt-fuzzer/` project currently provides:

- clone-only Python smoke flow for branch-event solving and patch replay;
- format-aware PPD and document generators;
- multi-target parser monitoring across CUPS Raster, PWG Raster, PDF, image,
  text, PostScript, and command-stream filters;
- AFL++ integration scripts and dictionaries;
- crash classification, deduplication, and corpus-retention utilities;
- documentation for coverage-discovery mode and expanded parser support.

## Research Direction

- Use grammar-aware and state-aware templates to keep generated inputs valid
  long enough to reach deeper filter logic.
- Add coverage-guided scheduling to avoid spending most time on already-known
  shallow states.
- Use SMT-style constraint solving for byte-level repairs and cross-input
  consistency, especially between PPD configuration and document headers.
- Evaluate mutation strategies with reproducible experiment matrices and
  clear reached/triggered/detected oracles.

## Repository Placement

The copied project lives under:

```text
smt-fuzzer/
```

The project is self-contained for its Python smoke tests. Real CUPS filter
campaigns still require local OpenPrinting builds and sanitizer-enabled target
binaries.
