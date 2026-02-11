uv=uv

check:
	$(uv) run pytest -vv $(pytest_args) tests

lint:
	$(uv) run ruff check .
	$(uv) run ruff format --check .

lint-fix:
	$(uv) run ruff check --fix .
	$(uv) run ruff format .

.PHONY: check lint lint-fix
