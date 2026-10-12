# Devices: inventory, encrypted credentials and connection tests

Step 3 adds administrator-triggered, read-only connection tests to the existing
Devices page. Saving a device still never contacts a router. Device deletion
remains database-only.

Automatic RAW provisioning is a per-device database setting, enabled by default
for all existing and newly added MikroTik devices after migration 0007. Public IP
Save and Retry automatically validate saved API credentials and RAW preflight
before the first write or after a device edit. Explicit Disable is still available.
For a device that was explicitly disabled, open Devices > Actions > RAW provisioning. Run read-only validation with a
public IP, review the exact saved endpoint and interface, and explicitly
authorize live writes. Validation tests connectivity and credentials, verifies
the interface, and checks existing RAW rules; it cannot create or modify rules.
Successful validation is valid for 15 minutes before authorization. Authorization
records the administrator and time and applies to future Public IP Save and
Retry actions. Enabling the setting alone does not provision existing records;
use Retry Provisioning for them. Disabling the setting retains all router rules.
Device edits preserve automatic provisioning enablement. Endpoint, credential,
interface, enabled-state or device-type changes invalidate the saved profile
validation; the next Public IP Save or Retry automatically tests and preflights
the current configuration before renewing its fingerprint. Explicit Disable
still stops provisioning. Name/description edits need no revalidation. Use migration 0007 before
running this version. No source edits or hardcoded device IDs are needed.

## Server configuration

Install the pinned runtime dependencies with the project virtual environment:

    .\venv\Scripts\python.exe -m pip install -r requirements.txt

On Windows, provision the key once without displaying it:

    .\venv\Scripts\python.exe manage.py configure_device_encryption --persist-windows-user

This stores NETSHIELD_DEVICE_ENCRYPTION_KEY in the current Windows user's persistent
environment (HKCU Environment), outside the project and database. Existing keys
are reused. Configuration conflicts, invalid keys and a missing original key for
existing devices stop setup; no replacement is generated. Back up the key only in
a trusted secret manager. Do not print it, paste it into chat, or commit it.

Start or restart NetShield using:

    .\start-netshield.ps1

The launcher loads the same persistent key into the server process on every start,
checks encryption, and never generates a key. It also rejects a conflicting process
key. The setup command and launcher must run as the Windows account that runs the
server. Old terminals and already-running servers do not automatically inherit a
changed user environment; restart using the launcher. For a service deployment,
supply the same key through that service account's managed environment.

Verification without secret output:

    .\venv\Scripts\python.exe manage.py configure_device_encryption

The key must be a URL-safe base64-encoded 32-byte Fernet key independent of Django
SECRET_KEY. Credential operations fail closed without a valid key. Losing the key
or replacing it without re-encrypting stored passwords prevents decryption. Tests
use ephemeral keys and random passwords. .gitignore excludes local .env/key files,
SQLite and backups; the persistent user key is never written into project files.

## Local development access

For a one-time administrator setup and a persistent 30-day local login, see
[LOCAL_DEVELOPMENT.md](../LOCAL_DEVELOPMENT.md). Use .\start-netshield-local.ps1
to opt into loopback-only local settings. Normal deployment settings and
administrator authorization are unchanged.

## Device access and saving

Visit /devices/. Anonymous users are sent to /devices/login/. Any active Django
user can view inventory. Active staff users and superusers are administrators and
can add devices. Existing Django account permissions are used; no default account
or hardcoded password is created. If needed, create an administrator interactively:

    .\venv\Scripts\python.exe manage.py createsuperuser

The existing Add Device form sends a CSRF-protected POST to /devices/add/. It
validates IPs, port 1–65535, required fields, device type, SSL choice and duplicate
IP/port endpoints. Passwords are encrypted before persistence and never redisplayed
on validation errors. Success appears only after the database transaction succeeds.
Saving does not contact a router. Device type selects a stored inventory category;
connection testing currently supports only enabled MikroTik devices.

Inventory queries explicitly select only safe fields, omitting username and
ciphertext. Untested devices read "Not Tested". Online/Offline mean only that the
last connection test succeeded/failed, with its timestamp and sanitized error.
They do not establish current reachability. CPU and RAM are snapshots, cleared
after a failed test. Traffic and PPS remain "Not available". The last retrieved
hardware model may remain after failure. Disabled is a separate saved setting.
Edit/Delete/Monitor/Details actions remain disabled; the existing details panel
shows information returned by a connection test. Inventory uses no-store headers.

## Model contract

Device.set_password() encrypts a supplied password in memory; Device.save()
validates the instance and persists ciphertext. Device.get_password() is for
server-side services only. Do not log its return value. The storage field rejects
plaintext even in ORM bulk writes and is excluded from standard Django serializers
and model forms. Future responses must use explicit safe field allowlists and
must never return credentials. Never use raw SQL to write device credentials.

Management IPs are canonical IPv4/IPv6 literals (no hostnames or scope IDs).
Management IP plus API port identifies a unique endpoint. Ports must be 1–65535;
normal saves validate fields, and database constraints enforce uniqueness and
port bounds even for bulk operations. Bulk operations bypass normal model
validation; use validated save() for device creation and updates.

API-SSL is the default (use_ssl=True, port 8729). Plain API can be configured
explicitly using use_ssl=False and the router's actual API port (usually 8728).
The port remains explicit and is not automatically rewritten when transport
changes. No connections are made when saving devices. Connection errors contain
fixed sanitized messages, never raw API exceptions.

## Read-only connection testing

Restart with .\start-netshield-local.ps1, sign in as an administrator, open
Devices, and choose Actions > Test Connection on an enabled MikroTik row.
The table and existing details panel update without a page reload. CPU, uptime,
total/free/used RAM, system identity, RouterOS version and model come from
/system/identity and /system/resource read requests. No router configuration
commands are sent. Only saved device IDs are accepted by POST
/devices/<id>/test-connection/; browser-provided targets are rejected.

Both settings profiles load the explicit deployment policy from
`netshield/device_management_allowlist.json`. Normal settings use
`allowed_networks`; local settings also use `local_additional_networks`.
The existing approved entries are preserved in that configuration file.
`NETSHIELD_DEVICE_ALLOWED_NETWORKS`, when present, replaces the entire file
policy for either profile with comma-separated strict IP/CIDR entries.
An empty environment value or a missing file denies all. Invalid entries fail
closed. Add only administrator-approved hosts or subnets, then restart Django
after changing the file or environment. The startup key is reused, never regenerated.

Test Connection and RAW provisioning enforce the same saved-address validator.
Rejected targets produce server-side diagnostics in `runtime/logs/provisioning.log`
with device ID, canonical management IP, policy source, applied networks and
reason; credentials and malformed input are excluded. Browser errors omit the
policy contents. A policy correction needs no database change or migration.

API-SSL always requires a trusted certificate with the saved management IP in its
subject alternative names. For an internal CA, set NETSHIELD_DEVICE_TLS_CA_FILE
to the server-side PEM CA file path; do not put a router private key there.
A certificate or TLS failure never falls back to plaintext. Plain API is used
only for profiles explicitly saved with API-SSL disabled.

The connection/socket timeout is 3 seconds per operation, including TCP/TLS and
API reads. The browser stops waiting after 30 seconds; that is not a server-side
total deadline. Refresh after a browser timeout to see any completed result.
Connections are disconnected in all service exit paths. No background polling
or Dashboard monitoring behavior is changed.

## Verification

    .\venv\Scripts\python.exe manage.py check
    .\venv\Scripts\python.exe manage.py makemigrations --check --dry-run
    .\venv\Scripts\python.exe manage.py test devices
    .\venv\Scripts\python.exe manage.py migrate --check

Back up SQLite using its online backup API before applying migrations. Step 3 adds
0002_connection_snapshots for test history and real system snapshots. Existing monitoring services, endpoints and
Dashboard/theme assets remain unchanged.

References: [Fernet documentation](https://cryptography.io/en/latest/fernet/) and
[Django model validation](https://docs.djangoproject.com/en/6.1/ref/models/instances/#validating-objects).


## Step 5 incoming monitoring interface

Devices > Actions offers a read-only Load interfaces action and local Save
interface setting. There is no assumed interface. The Add Device form accepts an
optional explicit incoming interface name. Configuration changes invalidate Public
IP rule verification without altering router rules or device credentials.

Automatic Public IP RAW provisioning is implemented but hard-disabled pending
separate approval. See [Step 5 report](../public_ips/STEP5_REPORT.md). The existing
Test Connection and Dashboard behavior are preserved.
## NOC inventory presentation

Devices opens in Router Grid with a Matrix Table alternative. Both views share
the same saved-device rows and action forms. Search matches name, management IP
and model; filters combine last test and RAW authorization state. Card badges
refer to the last recorded connection test, never continuous reachability.
CPU/RAM bars use real saved snapshots and hide when measurements are unavailable.

Inspect opens a keyboard-accessible dialog with Overview, Assigned Public IPs,
RAW Provisioning, Connection Details and Activity / Audit tabs. History contains
actual recorded changes and provisioning attempts. Errors remain in the
inspector rather than expanding every inventory row. Inventory GET requests
do not connect to routers, and no new polling was added. Existing theme tokens
and the light/dark preference are preserved.

UI checks: `node --test devices/tests/noc_ui.test.cjs` and Django
`devices.tests.test_noc_ui`. Existing management, connection and provisioning
tests cover the retained backend actions.

