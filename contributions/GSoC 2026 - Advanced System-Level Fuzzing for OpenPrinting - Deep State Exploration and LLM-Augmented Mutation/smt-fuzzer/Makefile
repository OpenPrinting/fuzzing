.PHONY: setup check-env check-cups-filters validate smoke test plan-experiment afl-build-env afl-plan multitarget-monitor local-cups-filters asan-cups-filters-plan asan-cups-filters explore-monitor arithmetic-explore

PYTHON ?= python3

setup:
	scripts/setup_tui.sh

check-env:
	scripts/check_env.sh

check-cups-filters:
	scripts/check_cups_filters_targets.sh

validate:
	PYTHONPATH=src $(PYTHON) -m smt_fuzzer.cli validate --configs configs

smoke:
	scripts/run_smoke.sh

test:
	$(PYTHON) -m unittest discover -s tests

plan-experiment:
	PYTHONPATH=src $(PYTHON) -m smt_fuzzer.cli plan-experiment --configs configs --targets 3 --trials 10 --hours 24

afl-build-env:
	PYTHONPATH=src $(PYTHON) -m smt_fuzzer.cli afl-build-env --configs configs

afl-plan:
	PYTHONPATH=src $(PYTHON) -m smt_fuzzer.cli afl-prepare --target ppd_ipp_parser --config A1 --binary harnesses/bin/ppd_ipp_parser

multitarget-monitor:
	scripts/run_multitarget_ppd_fuzz.sh 1 4

local-cups-filters:
	scripts/run_local_cups_filters_campaign.sh "$${SMT_FUZZER_FILTER_ROOT:-/usr/lib/cups/filter}" 60 4 5

asan-cups-filters-plan:
	scripts/print_cups_filters_build_plan.sh

asan-cups-filters:
	scripts/run_asan_cups_filters_campaign.sh "$${SMT_FUZZER_ASAN_ROOT:-$$(pwd)/work/openprinting-asan}" 60 4 5

explore-monitor:
	scripts/run_explore_ppd_fuzz.sh "" 4

arithmetic-explore:
	scripts/run_arithmetic_explore.sh 600 4 5
