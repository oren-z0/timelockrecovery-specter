# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A [Specter Desktop](https://github.com/cryptoadvance/specter-desktop) extension for creating Bitcoin timelock-recovery plans. It produces two pre-signed transactions:
1. **Alert transaction** — moves funds to a new address in the same wallet with a relative timelock
2. **Recovery transaction** — sends to inheritance/backup addresses, can be mined after the expiry of the timelock (relative to the alert transaction).

An optional **cancellation transaction** lets the user abort during the timelock window.

PyPI package: `specterext-timelockrecovery`

## Development Commands

Install in editable mode (run from repo root):
```bash
pip install -e .
```

Run tests:
```bash
pytest
pytest tests/conftest.py  # single file
pytest -m "not slow"      # skip slow tests
```

Run as standalone app (development):
```bash
python -m oren-z0.specterext.timelockrecovery
# Options: --host, --port, --ssl, --debug, --log-level
```

## Architecture

All source lives under `src/oren-z0/specterext/timelockrecovery/`.

### Core Files

- **[service.py](src/oren-z0/specterext/timelockrecovery/service.py)** — `TimelockrecoveryService` extends Specter's `Service`. Handles recovery plan persistence via `ServiceEncryptedStorage`, address reservation (alert address, cancellation address), and wallet association.

- **[controller.py](src/oren-z0/specterext/timelockrecovery/controller.py)** — Flask blueprint with all routes. The main flow is a 6-step wizard (`/step1` through `/step6`) that builds and signs the transaction chain. Also exposes `/plans`, `/plans/<id>`, `/settings`, and utility endpoints for PSBT size estimation and combining.

- **[config.py](src/oren-z0/specterext/timelockrecovery/config.py)** — `BaseConfig` / `ProductionConfig` for extension-level config.

- **[app_config.py](src/oren-z0/specterext/timelockrecovery/app_config.py)** — `AppProductionConfig` for running as a standalone Flask app (sets data folder, extension list, redirect).

### Wizard Flow (controller.py)

| Step | Purpose |
|------|---------|
| 1 | Select wallet |
| 2 | Select UTXOs, set timelock duration and destination addresses |
| 3 | Build and sign the alert PSBT |
| 4 | Build and sign the recovery PSBT (CSV timelock) |
| 5 | Build and sign the optional cancellation PSBT |
| 6 | Save the finalized recovery plan |

### Key Bitcoin Details

- **Timelock encoding**: Uses relative time-based locks (`0x00400000` flag, value in 512-second units).
- **PSBT formats**: Accepts Base64, UR:BYTES, and Electrum Base43 — all normalized internally.
- **CPFP reserve**: 600 sats pre-allocated per destination output for fee bumping.
- **SegWit only**: Legacy-address wallets are explicitly rejected.
- **No Liquid Network support**.

### Testing

Tests use `pytest-bitcoind` and `pytest-elementsd` fixtures (Bitcoin Core v22.0.0, Elements v0.21.0.2). Fixtures are in `tests/fix_*.py` files. The `conftest.py` wires up device, wallet, key, and seed fixtures for integration testing.
