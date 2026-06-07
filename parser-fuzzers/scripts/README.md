# Script Map

Scripts are grouped by layer. Most scripts are thin wrappers around the Python
CLI and keep output under `work/` or `findings/`.

## Smoke And Environment

- `check_env.sh`: report Python/AFL++ tool availability.
- `run_smoke.sh`: clone-only solver-to-patch smoke test.
- `afl_build_env.sh`: print AFL++ compiler environment.
- `afl_coverage_env.sh`: print AFL++/ASan-oriented build environment.
- `llvm_coverage_env.sh`: print LLVM source-coverage build environment.
- `merge_llvm_coverage.sh`: merge LLVM profile output.

## AFL++ Boundary

- `run_afl.sh`: standard AFL++ command builder/runner.
- `build_afl_template_probe.sh`: build the clone-only AFL++ instrumented probe harness.
- `run_template_afl_loop.sh`: run template generation, standard AFL++, frontier import, and feedback-template generation in one file-backed cycle.
- `run_afl_pwg_frontier.sh`: AFL++ frontier campaign for PWG-derived targets.
- `afl_direct_filter_target.sh`: direct filter wrapper for AFL++ `@@`.
- `prepare_afl_frontier_corpus.py`: export retained documents as AFL++ seeds.
- `import_afl_frontier_feedback.py`: import AFL++ queue/crashes as feedback.
- `afl_stats_snapshot.py`: compact AFL++ stats reader.
- `run_afl_feedback_smt_round.sh`: run a template round from AFL++ feedback.
- `archive_afl_crashes.py`: archive AFL++ crashes/hangs and optionally delete
  raw crash/hang files after the archive succeeds.
- `run_afl_pwg_bundle.sh`: standard PWG bundle AFL++ runner. Set
  `SMT_AFL_BUNDLE_MAX_GB=<n>` to print campaign size and stop AFL++ when the
  campaign directory reaches that limit.

## Template And Runner Campaigns

- `run_template_runner_campaign.sh`: template/runner campaign that asks for
  the filter root before executing configured direct-filter targets.
- `run_multitarget_ppd_fuzz.sh`: multi-target PPD/document monitor.
- `run_explore_ppd_fuzz.sh`: less-directed parser exploration.
- `run_general_parser_campaign.sh`: general parser campaign.
- `run_coverage_discovery_campaign.sh`: coverage-discovery campaign.
- `run_deep_coverage_campaign.sh`: deeper coverage-discovery campaign.
- `run_cold_semantic_campaign.sh`: cold parser semantic campaign.
- `run_feedback_template_campaign.sh`: feedback-driven template run.
- `run_structural_template_campaign.sh`: structural template run.
- `run_arithmetic_explore.sh`: cross-input arithmetic exploration.

Longer campaigns should be launched with explicit `parser_fuzzers.cli`
command lines so duration, disk limits, configs, and targets are visible in the
run log.

## Image Campaigns

- `run_image_feedback_campaign.sh`: image parser feedback campaign.
- `run_image_deep_campaign.sh`: focused image parser campaign.
- `run_image_cycle_campaign.sh`: multi-round image parser cycle.

## Triage

- `replay_asan_filter.sh`: replay a retained case under ASan-built filters.
- `gdb_crash_filter.sh`: run a case under GDB.
- `run_baseline_comparison.sh`: local baseline comparison helper.
- `build_historical_reachability_matrix.py`: summarize private replay evidence
  against configured parser/harness coverage. Keep generated reports private
  unless the contents are safe to disclose.
