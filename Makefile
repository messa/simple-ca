uv=uv

check:
	$(uv) run pytest -vs $(pytest_args) tests

.PHONY: check
