# SPDX-License-Identifier: Apache-2.0

PYTHON ?= python3

.PHONY: check check-shell

check: check-shell
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -S -m unittest discover -s tests -v

check-shell:
	bash -n oss_fuzz_build.sh
	bash -n harnesses/libfuzzer/v3/build_local.sh
	bash -n harnesses/libfuzzer/v3/targets.sh
	bash -n ../projects/cups-filters/oss_fuzz_build.sh
