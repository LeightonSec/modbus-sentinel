.PHONY: pin pin-dev

# Pin exact versions + generate hashes for supply chain security.
# Requires: pip install uv
#
# Lockfiles MUST be --universal: a single-environment compile (e.g. on one
# Python or one OS) silently drops conditional deps — exceptiongroup on
# Python < 3.11, colorama on win32 — which then fail under pip's implicit
# --require-hashes mode on the missing target. --universal captures every
# python-version and platform marker so the lockfile installs everywhere
# inside requires-python (>=3.10).
pin:
	uv pip compile --universal --python-version 3.10 --generate-hashes pyproject.toml -o requirements.txt

pin-dev:
	uv pip compile --universal --python-version 3.10 --generate-hashes requirements-dev.in -o requirements-dev.txt
