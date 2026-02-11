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

- **`RootCA`** class (in `simple_ca/ca.py`) — root Certificate Authority. Inherits from `_CABase`.
  - `RootCA.init_ca(org, cn='CA', *, days=DEFAULT_VALIDITY_DAYS)` — class method, creates a new root CA
  - `RootCA(cert, key, key_password)` — construct from existing PEM data
  - `root.create_intermediate_ca(org, cn='Intermediate CA', *, days=DEFAULT_VALIDITY_DAYS)` — creates an `IntermediateCA` signed by this CA
  - `root.create_server_cert(cn, org, dc=None, san=None, *, days=DEFAULT_VALIDITY_DAYS)` — creates a server certificate, returns `CertKeyPair`
- **`IntermediateCA`** class (in `simple_ca/ca.py`) — intermediate Certificate Authority. Inherits from `_CABase`.
  - `IntermediateCA(cert, key, key_password, *, parent=ca_obj)` — construct from existing PEM data with parent CA object
  - `IntermediateCA(cert, key, key_password, *, parent_ca_cert=pem_str)` — construct from existing PEM data with parent cert PEM
  - `inter.create_server_cert(...)` — same as RootCA
  - `inter.create_intermediate_ca(...)` — same as RootCA
- **`CA`** — backward-compatible alias for `RootCA`
- **`SimpleCA`** class (in `simple_ca/simple_ca.py`) — legacy API, delegates to `CA`
- **`CertKeyPair`** dataclass (in `simple_ca/types.py`) — holds `cert`, `key`, `key_password`, `cert_chain`, and `serial` (all strings, PEM-encoded; `cert_chain` and `serial` default to `None`)
- **`DEFAULT_VALIDITY_DAYS`** constant (in `simple_ca/types.py`) — default certificate validity period (10000 days)

All are exported from `simple_ca/__init__.py`.

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
