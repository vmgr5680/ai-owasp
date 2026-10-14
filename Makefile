PYTHON ?= python3
PY := .venv/bin/python

.PHONY: install test parts runs clean

install:            ## venv + package (standard library only, plus pytest)
	$(PYTHON) -m venv .venv
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -e '.[dev]'

test:               ## every article's printed claims, plus the library
	$(PY) -m pytest

parts:              ## re-run every article's examples, part by part
	@for f in parts/p*.py; do printf '\n##### %s\n' $$f; $(PY) $$f || exit 1; done

runs:               ## capture every script's output into runs/ (commit these)
	@mkdir -p runs
	@for f in parts/p*.py; do $(PY) $$f > runs/$$(basename $$f .py).out 2>&1 || exit 1; done
	@ls runs

clean:
	rm -rf .pytest_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
