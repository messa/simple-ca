check: venv/packages_installed
	PYTHONDONTWRITEBYTECODE=1 venv/bin/python3 -m pytest -vs tests

venv/packages_installed:
	test -f venv/packages_installed || python3 -m venv venv
	venv/bin/pip install -r requirements-tests.txt
	venv/bin/pip install -e .
	touch $@

.PHONY: check
