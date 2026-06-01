# Advanced System-Level Fuzzing for OpenPrinting: Deep State Exploration and LLM-Augmented Mutation

**Security- and fuzzing-related project**

Program: Google Summer of Code 2026

Status: Draft proposal

## Project Description

OpenPrinting components process a wide range of structured inputs, including
PPD files, IPP attributes, CUPS Raster, PWG Raster, PDF, PostScript, images,
text, and command streams. Many interesting bugs require valid cross-input
state: a printer description selects filter behavior, while the document input
drives parser and renderer state. Pure byte-level fuzzing often spends most of
its time before these deeper states are reached.

This project proposes a system-level fuzzing workflow for OpenPrinting that
combines:

- format-aware seed and template generation;
- multi-filter direct execution and replay;
- coverage-guided corpus retention;
- SMT-style byte repair for branch events and cross-input consistency;
- optional AFL++ integration for long-running campaigns;
- mutation strategies assisted by model-generated templates or dictionaries,
  while keeping replay, validation, and evaluation fully reproducible.

## Current Prototype

The included `smt-fuzzer/` snapshot provides a runnable prototype with:

- Python smoke tests for SMT solving and patch application;
- metadata validation for ground-truth bug suites and seed policy;
- PPD and document templates for multiple OpenPrinting parser paths;
- direct-filter monitoring across CUPS Raster, PWG Raster, PDF, image, text,
  PostScript, and command-stream filters;
- AFL++ launch helpers, dictionaries, and environment scripts;
- crash deduplication and corpus-retention utilities.

## Expected Outcome

The expected outcome is a reproducible evaluation framework that can compare
baseline fuzzing, dictionary-guided fuzzing, grammar-aware generation, and
SMT-assisted mutation on OpenPrinting targets, with clear reached, triggered,
and detected oracles.

The project should also produce reusable harnesses, seeds, dictionaries, and
documentation suitable for future OpenPrinting fuzzing integrations.
