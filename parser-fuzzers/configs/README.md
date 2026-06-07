# Config Map

Configs define targets, experiment rows, and campaign profiles.

## Core Configs

- `experiment.yaml`: A0-A4 experiment matrix.
- `targets.yaml`: generic target metadata and dictionaries.
- `afl.yaml`: AFL++ command defaults.
- `parser_targets.yaml`: initial multi-target PPD/document config.

## General Parser Campaigns

- `parser_targets_general.yaml`: broad low-direction parser targets.
- `parser_targets_coverage.yaml`: coverage-discovery targets.
- `parser_targets_auto_hybrid.yaml`: current hybrid automatic exploration.
- `parser_targets_cold_semantic.yaml`: cold parser semantic expansion.

## Image Campaigns

- `parser_targets_image_feedback.yaml`: broad image feedback targets.
- `parser_targets_image_imagetopdf_feedback.yaml`: imagetopdf focus.
- `parser_targets_image_imagetops_feedback.yaml`: imagetops focus.
- `parser_targets_image_imagetoraster_feedback.yaml`: imagetoraster focus.

## AFL++ Feedback Campaigns

- `parser_targets_afl_pwg_feedback.yaml`: PWG AFL++ feedback targets.
- `parser_targets_afl_pwg_pdf_deep.yaml`: AFL++-seeded PDF/PWG deep target.

## Underexplored Parser Campaigns

- `parser_targets_underexplored.yaml`: underexplored parser sweep.
- `parser_targets_underexplored_feedback30.yaml`: 30-minute feedback variant.
- `parser_targets_underexplored_semantic.yaml`: semantic variant.

## Older Or Focused Profiles

- `parser_targets_explore.yaml`: earlier exploration profile.
- `parser_targets_feedback.yaml`: earlier feedback profile.
- `parser_targets_structural.yaml`: structural template profile.

Generated local coverage configs under `work/` are intentionally not tracked.
