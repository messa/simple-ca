check: local/venv34
	PYTHONDONTWRITEBYTECODE=1 local/venv34/bin/py.test -vs tests

local/venv34:
	[ -d local/venv34 ] || mkdir -p local && pyvenv-3.4 local/venv34
	local/venv34/bin/pip install -U pip
	local/venv34/bin/pip install pytest
	local/venv34/bin/pip install -e .

.PHONY: check
