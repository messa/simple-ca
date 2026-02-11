# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

simple-ca is a Python library that wraps the `openssl` CLI to create a custom Certificate Authority (CA) and sign server certificates. It requires `openssl` to be installed on the system.

## Commands

### Run tests
```
make check
```
This runs `uv run pytest -vs tests`.

### Run a single test
```
uv run pytest -vs tests/test_simple_ca.py::test_create_server_cert
```

### Lint
```
make lint
```
This runs `ruff check` and `ruff format --check`.

### Lint and auto-fix
```
make lint-fix
```

## Architecture

### Public API

- **`CA`** class (in `simple_ca/ca.py`) — the recommended API. Inherits from `CKP` namedtuple.
  - `CA.init_ca(org, cn)` — class method, creates a new root CA and returns a `CA` instance
  - `ca.create_intermediate_ca(org, cn)` — creates an intermediate CA signed by this CA, returns a new `CA` instance
  - `ca.create_server_cert(cn, org, dc, san)` — creates a server certificate signed by this CA, returns `CKP`
- **`SimpleCA`** class (in `simple_ca/simple_ca.py`) — legacy API, delegates to `CA`
- **`CKP`** namedtuple (in `simple_ca/types.py`) — holds `cert`, `key`, `key_password`, and `cert_chain` (all strings, PEM-encoded; `cert_chain` is optional and contains the full certificate chain for TLS)

All three are exported from `simple_ca/__init__.py`.

### Internal structure

- `simple_ca/openssl_cli.py` — `OpenSSLCLI` class: thin wrapper that calls the `openssl` binary via subprocess
- `simple_ca/functions/init_ca.py` — `InitCA`: creates CA key+cert using temp directory with openssl config files
- `simple_ca/functions/create_intermediate_ca.py` — `CreateIntermediateCA`: creates intermediate CA key, CSR, and cert signed by parent CA (with `CA:true, pathlen:0` extensions)
- `simple_ca/functions/create_server_cert.py` — `CreateServerCert`: creates server key, CSR, and cert signed by CA; supports SAN (Subject Alternative Names) for DNS names and IP addresses

Each function class works by writing openssl config files and key material to a `TemporaryDirectory`, invoking openssl commands, then reading back the results. The temp directory is cleaned up automatically.

## Code Style

- Prefer `from A import B` style imports instead of `import A`.

## Testing

- In pytest tests, use the `tmp_path` fixture for temporary files and directories.

## Packaging

Uses `pyproject.toml` with hatchling build backend. Managed with `uv`. No runtime dependencies beyond Python stdlib and the `openssl` system command. Dev dependencies: `pytest`, `ruff`.
