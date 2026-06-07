.PHONY: check-env validate smoke test plan-experiment afl-build-env afl-plan multitarget-monitor explore-monitor arithmetic-explore

PYTHON ?= python3

check-env:
	scripts/check_env.sh

validate:
	PYTHONPATH=src $(PYTHON) -m parser_fuzzers.cli validate --bugs bugs --configs configs

smoke:
	scripts/run_smoke.sh

test:
	$(PYTHON) -m unittest discover -s tests

plan-experiment:
	PYTHONPATH=src $(PYTHON) -m parser_fuzzers.cli plan-experiment --configs configs --targets 3 --trials 10 --hours 24

afl-build-env:
	PYTHONPATH=src $(PYTHON) -m parser_fuzzers.cli afl-build-env --configs configs

afl-plan:
	PYTHONPATH=src $(PYTHON) -m parser_fuzzers.cli afl-prepare --target ppd_ipp_parser --config A1 --binary harnesses/bin/ppd_ipp_parser

multitarget-monitor:
	scripts/run_multitarget_ppd_fuzz.sh 1 4

explore-monitor:
	scripts/run_explore_ppd_fuzz.sh "" 4

arithmetic-explore:
	scripts/run_arithmetic_explore.sh 600 4 5
