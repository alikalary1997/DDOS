# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

NetShield is a Django 6.1 app for monitoring MikroTik/RouterOS devices: inventory, SNMP sensors, public-IP firewall provisioning, live traffic monitoring, and DDoS detection. SQLite-backed, Windows-first (the device encryption key lives in the Windows user registry and `configure_device_encryption` uses `winreg`).

## Commands

The project runs from a venv at `venv/`. Use `venv\Scripts\python.exe` (Windows) directly rather than relying on an activated shell.

```powershell
# Run the server (normal profile)
.\start-netshield.ps1                 # binds 127.0.0.1:8000; verifies device encryption first
# Run the server (local development profile — loopback-only, 30-day sessions)
.\start-netshield-local.ps1 -Port 8000

# Direct Django usage
.\venv\Scripts\python.exe manage.py <command>
.\venv\Scripts\python.exe manage.py createsuperuser
.\venv\Scripts\python.exe manage.py migrate
.\venv\Scripts\python.exe manage.py makemigrations

# Python tests (Django TestCase)
.\venv\Scripts\python.exe manage.py test                         # all apps
.\venv\Scripts\python.exe manage.py test sensors                 # one app
.\venv\Scripts\python.exe manage.py test devices.tests.test_connection   # one module
.\venv\Scripts\python.exe manage.py test devices.tests.test_connection.ClassName.test_method  # one test

# JavaScript UI tests (Node built-in runner; no package.json / npm install)
node --test monitor/test_detection_ui.cjs
node --test monitor/ sensors/tests/ public_ips/tests/ devices/tests/   # by directory
```

Dependencies: `pip install -r requirements.txt` (Django 6.1.2, routeros-api, cryptography, pysnmp).

## Settings profiles

Two settings modules, selected via `--settings`:
- `netshield.settings` — normal profile (default in `manage.py`).
- `netshield.settings_local` — `from .settings import *`, adds `LocalDevelopmentOnlyMiddleware` (rejects non-loopback peers, nonlocal Host headers, and any forwarded/proxy headers — fails closed), a distinct `netshield_local_sessionid` cookie, and 30-day DB-backed sessions. Only reachable directly from the PC. See `LOCAL_DEVELOPMENT.md`.

`DEBUG = True` and a placeholder `SECRET_KEY` are committed — this is not a production configuration.

## Architecture

Django project `netshield` with five apps. URL tree is rooted in `monitor.urls`, which includes `devices.urls` and `public_ips.urls`; `sensors.urls` wires in under devices/monitor views.

- **devices** — `Device` inventory and the RouterOS transport layer. All business logic lives under `devices/services/`: `router_session.py` (RouterOS API session via routeros-api, API-SSL only), `credentials.py` (Fernet encrypt/decrypt), `targets.py` (target validation), `router_lock.py`, `connection.py`, `management.py`, `provisioning_authorization.py`.
- **public_ips** — `PublicIP` assignments, RAW firewall provisioning, live traffic monitoring. Services in `public_ips/services/` (`provisioning.py`, `monitoring.py`, `monitoring_runtime.py`, `rules.py`, `preflight.py`, etc.). Owns the monitoring worker subprocess.
- **monitor** — dashboard, DDoS detection, settings, reports, alerts. `monitor/services/dashboard_data.py` assembles the dashboard JSON polled by the UI; `detection.py` runs the detection pipeline against `DDoSDetectionSettings` thresholds and `DetectionPolicy` hysteresis/confirmation rules, recording `DetectionEvent`s.
- **sensors** — SNMP (PySNMP SNMPv2c, read-only GET/GETNEXT — no SET/writes) traffic/uptime/CPU sensors, independent of RouterOS API credentials. `Sensor` + `SensorSample` time series. See `sensors/README.md`.
- **netshield** — project config: settings, `device_policy.py` (allowlist loader), `local_development.py` (middleware).

### Service-layer convention
Views are thin: auth decorators, request parsing, and a call into the app's `services/` package which holds all business logic. Put new logic in `services/`, not in views. `may_add_devices(request.user)` (from `devices.views`) is the shared staff/superuser gate.

### Background workers
Long-running polling runs as **detached subprocesses** of `manage.py`, not threads:
- SNMP sensor worker: `manage.py poll_sensors`, launched by `sensors/runtime.py::ensure_worker()`, logs to `runtime/snmp/worker.log`.
- Public-IP monitoring worker: launched by `public_ips/services/monitoring_runtime.py::launch()`, logs to `runtime/app-monitoring.log`.

Workers start **only on a deliberate admin POST** (Add/Start), never on page load or Django restart. Lifecycle is tracked by singleton runtime models (`SensorRuntime`, `MonitoringRun`, both `pk=1`) plus file locks. Access to a single router is serialized across provisioning/discovery/polling by `router_lock(device_id)` (`devices/services/router_lock.py`), which uses OS file locks (`msvcrt` on Windows, `fcntl` elsewhere) and raises `RouterBusy` when contended — callers surface this as HTTP 409. The `runtime/` directory (lock files, logs) is gitignored.

## Security posture (preserve these invariants)

- **Device credentials** are Fernet-encrypted with `NETSHIELD_DEVICE_ENCRYPTION_KEY`, supplied only by the server environment (Windows user registry). `configure_device_encryption` verifies/provisions the key without revealing it. Never log, serialize, or render credentials/communities; service functions use `@sensitive_variables()` and return only safe, non-disclosing error messages (`CredentialError`, `RouterAccessError`).
- **Device network allowlist is deny-by-default.** `device_policy.load_device_policy()` reads `netshield/device_management_allowlist.json` (or `NETSHIELD_DEVICE_ALLOWED_NETWORKS` env, which never falls back); a missing/empty config denies all connection tests.
- **RAW provisioning and RAW polling are gated OFF** (`NETSHIELD_RAW_PROVISIONING_ENABLED`, `NETSHIELD_RAW_POLLING_ENABLED` = `False`) pending a separately approved release. There is no runtime/browser switch.
- RouterOS connections require API-SSL with certificate verification; the code never falls back to plain API.

## Tests

Each app has both Django `TestCase` suites (`test_*.py`, usually under `<app>/tests/`) and Node `*.test.cjs`/`test_*.cjs` files that exercise the dashboard/settings JS by evaluating it in a hand-rolled DOM via `node:vm` + `node:test` (no browser, no npm deps). When changing UI JS under `*/static/*/js/`, run the matching `.cjs` tests.

Note: migrations are not fully clean — a `0002_sensorsample_ping_ms_alter_sensor_kind.py` migration is currently untracked in the sensors app. Run `makemigrations --check` before relying on migration state.
