# Prepared first live test — approval pending

No router writes have been performed. The later authorized read-only connection
attempt was refused; see the diagnostic findings at the end of this document.
Global provisioning remains disabled. The controlled release flag is false and
its approved target is unset. Browser Save/Retry cannot bypass those gates.

## Actual saved candidate (not the user's illustrative example)

| Field | Current saved value |
| --- | --- |
| Device | Home, ID 4 |
| Management IP / API port | 192.168.32.1 / 1122 |
| API-SSL preference | Enabled; verified TLS, no plaintext fallback |
| Saved device interface | ether5 |
| Public IP record | ID 6, 185.166.26.26 |
| Saved assignment interface | ether5 |
| Administrator actor | ID 1 |

If these are not the intended target, choose/configure the correct saved record
before approval. Do not use example addresses or interfaces as real targets.
The original persistent Windows user key was verified during diagnosis and
decrypted the saved password. A management command must load that original key,
as the launcher does. This device is blocked by the command environment's
management-network allowlist.
Run from the configured server environment using the original encryption key;
do not generate a replacement key for existing encrypted credentials. Review an
explicit target allowlist before any connection. TLS/connectivity/interface/RAW
checks have not been performed against the live router.

## Preview prepared now

```powershell
venv/Scripts/python.exe manage.py test_raw_provisioning_once 6
```

This prints the saved record's exact three API argument dictionaries. It performs
no database updates, router connection or writes. Credentials are not printed.

## Controlled execution after explicit authorization

1. Confirm the selected device, public IP, interface and administrator.
2. Back up SQLite again and use the configured NetShield server environment.
3. Run the read-only preflight:

   ```powershell
   venv/Scripts/python.exe manage.py check_raw_provisioning 4 185.166.26.26
   ```

   Stop on key/decryption, allowlist, connection, TLS, interface, duplicate, conflict
   or unsafe-order errors. Do not broaden the allowlist or disable TLS automatically.
4. Only after user authorization, release `CONTROLLED_LIVE_TEST_RELEASED` and set
   `APPROVED_LIVE_TEST_TARGET` in `services/controlled_test.py` to exactly
   `(6, 1, 4, "185.166.26.26", "ether5")`. Leave both global provisioning gates off.
5. Run once:

   ```powershell
   venv/Scripts/python.exe manage.py test_raw_provisioning_once 6 --apply --actor-id 1 --confirm-device-id 4 --confirm-address 185.166.26.26 --confirm-interface ether5
   ```

   The scope checks the whole saved connection profile before each add, only adds
   missing passthrough rules, and cannot perform historical cleanup. It verifies
   all three rules and audits the attempt. Failures retain the assignment; an
   approved retry rechecks rules, including uncertain prior API outcomes.
6. Reset the controlled release flag and target immediately afterward. The runtime
   scope closes even on failure; global browser Save/Retry remains disabled.

The expected new comments for this candidate are `MONITOR-185.166.26.26`,
`MONITOR-SYN-185.166.26.26`, and `MONITOR-UDP-185.166.26.26`. Only the first rule has
`in-interface=ether5`. No drop/reject, set, remove, move or router cleanup is allowed
in the test. Any rules added remain on the router; rollback removal would require
separate authorization. Device deletion remains database-only.

## Automatic Add Public IP after a separately approved release

The Add form now takes address, assigned device and optional description. It
copies the assigned device's saved interface into the assignment and never asks
for API credentials. Saving commits the assignment and calls audited provisioning
automatically. Global release is a separate approval from this controlled test.
Until then, Save reports approval pending and retains the record for Retry.

Read-only diagnosis on 2026-10-10: the original persistent Windows user key
decrypted the saved password. With an isolated host-only diagnostic allowlist,
the connection to 192.168.32.1:1122 was refused (Windows 10061). No interface or
RAW reads completed. Persistent target policy still needs review; the port must
accept the saved API-SSL connection before any write test. No router rules changed.
