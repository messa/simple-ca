# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

simple-ca is a Python library that wraps the `openssl` CLI to create a custom Certificate Authority (CA) and sign server certificates. It requires `openssl` to be installed on the system.

## Commands

### Run tests
```
make check
```
This creates a venv, installs dependencies + the package in editable mode, then runs pytest.

### Run tests directly (if venv already set up)
```
PYTHONDONTWRITEBYTECODE=1 venv/bin/python3 -m pytest -vs tests
```

### Run a single test
```
venv/bin/python3 -m pytest -vs tests/test_simple_ca.py::test_create_server_cert
```

## Architecture

### Public API

- **`CA`** class (in `simple_ca/ca.py`) — the recommended API. Inherits from `CKP` namedtuple.
  - `CA.init_ca(org, cn)` — class method, creates a new CA and returns a `CA` instance
  - `ca.create_server_cert(cn, org, dc, san)` — creates a server certificate signed by this CA, returns `CKP`
- **`SimpleCA`** class (in `simple_ca/simple_ca.py`) — legacy API, delegates to `CA`
- **`CKP`** namedtuple (in `simple_ca/types.py`) — holds `cert`, `key`, and `key_password` (all strings, PEM-encoded)

All three are exported from `simple_ca/__init__.py`.

### Internal structure

- `simple_ca/openssl_cli.py` — `OpenSSLCLI` class: thin wrapper that calls the `openssl` binary via subprocess
- `simple_ca/functions/init_ca.py` — `InitCA`: creates CA key+cert using temp directory with openssl config files
- `simple_ca/functions/create_server_cert.py` — `CreateServerCert`: creates server key, CSR, and cert signed by CA; supports SAN (Subject Alternative Names) for DNS names and IP addresses

Each function class works by writing openssl config files and key material to a `TemporaryDirectory`, invoking openssl commands, then reading back the results. The temp directory is cleaned up automatically.

## Packaging

Uses `setup.py` (no pyproject.toml). No runtime dependencies beyond Python stdlib and the `openssl` system command.
