.PHONY: pin pin-dev check

# Interpreter for local dev; defaults to the project venv so `make check` uses
# the same Python the tests were installed against, not system Python (which
# does not have the deps). CI overrides with `make check PY=python`, since it
# installs deps into the runner's interpreter.
PY ?= $(CURDIR)/.venv/bin/python

# Pin exact versions + generate hashes for supply chain security.
# Requires: pip install uv
#
# Lockfiles MUST be --universal: a single-environment compile (e.g. on one
# Python or one OS) silently drops conditional deps (exceptiongroup on
# Python < 3.11, colorama on win32) which then fail under pip's implicit
# --require-hashes mode on the missing target. --universal captures every
# python-version and platform marker so the lockfile installs everywhere
# inside requires-python (>=3.10).
pin:
	uv pip compile --universal --python-version 3.10 --generate-hashes pyproject.toml -o requirements.txt

pin-dev:
	uv pip compile --universal --python-version 3.10 --generate-hashes requirements-dev.in -o requirements-dev.txt

# What CI runs, runnable locally in one command. Each command is its own recipe
# line, so make halts on the first non-zero exit rather than reporting a green
# it did not earn. Order: prose gate, golden freshness, lint, tests.
check:
	$(PY) scripts/verify_prose.py
	$(PY) -m scripts.emit_golden --check
	$(PY) -m ruff check modbus_sentinel/ tests/
	$(PY) -m pytest -q
