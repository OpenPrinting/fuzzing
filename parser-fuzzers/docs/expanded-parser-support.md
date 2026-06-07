# Expanded Parser Support

Date: 2026-06-01

The coverage parser campaign now includes 20 direct-filter targets across these
input families:

- CUPS Raster: `rastertopclx`, `rastertoescpx`, `rastertops`
- PWG Raster: `pwgtoraster`, `pwgtopdf`, `pwgtopclm`
- PDF: `pdftopdf`, `pdftops`, `pdftoraster`, `mupdftopwg`
- Image: `imagetoraster`, `imagetopdf`, `imagetops`
- Text: `texttopdf`, `texttotext`
- PostScript/Ghostscript wrappers: `gstoraster`, `gstopdf`, `gstopxl`
- CUPS command streams: `commandtoescpx`, `commandtopclx`

## Inputs

`document_harness.py` now generates extension-aware structured documents:

- `.ras` CUPS Raster
- `.pwg` PWG Raster
- `.pdf` minimal PDF with valid xref
- `.ps` minimal PostScript
- `.png` plus PNM variants for image parsers
- `.txt` text parser inputs
- `.cmd` CUPS command inputs

The runner writes the correct `document.<ext>` name per case so filters that
infer type from the filename are exercised properly. Replay helpers search the
same extension set.

## Current Run Command

```bash
scripts/run_deep_coverage_campaign.sh 300 4 5
```

Equivalent CLI:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config configs/parser_targets_coverage.yaml \
  --work-root work/deep-coverage \
  --workers 4 \
  --timeout-sec 5 \
  --duration-sec 300 \
  --discard-stdout \
  --discovery-mode coverage
```

## Smoke Result

Command:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config configs/parser_targets_coverage.yaml \
  --work-root work/expanded-parser-smoke \
  --workers 4 \
  --cases-per-target 1 \
  --timeout-sec 5 \
  --discard-stdout \
  --discovery-mode coverage
```

Latest smoke directory:

```text
work/expanded-parser-smoke/20260601-130736
```

Result:

- Targets: 20
- Cases: 20
- Reached expected filter: 20
- Valid PPDs: 20
- Crashes: 0
- Timeouts: 0
- Retained feature cases: 20
- Coverage features: 90

One expected limitation remains: `pwgtopclm` currently reaches the wrapper but
returns an error because the synthetic PPD/input does not yet provide the
printer IPP attributes needed for PCLm output. It is retained as a parser entry
point, but deeper PCLm exploration needs an IPP-attribute template.
