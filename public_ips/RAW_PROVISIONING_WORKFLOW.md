# Final RAW provisioning workflow

Devices retain encrypted API credentials and a default incoming interface.
Each Public IP record stores its own `incoming_monitoring_interface`. Add Public
IP automatically copies the assigned device's saved interface, ignoring browser
interface overrides and asking only for IP, device and optional description.
Edit retains the explicit per-record interface configuration. Existing assignments receive their device's current
default once through migration 0005. Blank Edit form input uses an existing record
interface or copies the device default; missing defaults produce a form error.
Provisioning and polling subsequently use only the saved record interface.
The encryption key remains in `NETSHIELD_DEVICE_ENCRYPTION_KEY`, outside SQLite.
Public IP creation saves the assignment before attempting audited provisioning.
Failures retain the record and expose Retry Provisioning.

The exact rule specifications are in `services/rules.py`. All rules use
`prerouting`, `passthrough` and the selected public IPv4 destination:

| Comment | Protocol | TCP flags | Incoming interface |
| --- | --- | --- | --- |
| MONITOR-IP | unrestricted | unrestricted | saved Public IP record interface |
| MONITOR-SYN-IP | tcp | syn | unrestricted |
| MONITOR-UDP-IP | udp | unrestricted | unrestricted |

Correct existing rules are reused. Duplicate comments, conflicting properties,
and existing monitoring rules behind potentially terminating prerouting rules
stop provisioning before any add. Missing rules are added before the first
prerouting rule without moving or changing existing rules. Legacy SYN/UDP rules
with interface restrictions require manual review; this workflow does not edit
or remove them. Verification requires all three exact, safely placed rules.

## Read-only preflight

After automated tests, an administrator can run from the server environment:

```powershell
venv/Scripts/python.exe manage.py check_raw_provisioning DEVICE_ID PUBLIC_IPV4
```

Replace the arguments with a saved device ID and the intended real public IPv4.
This explicitly contacts the saved router using its encrypted credentials, reads
interfaces and RAW rules, checks conflicts and placement, and performs no writes
or database mutations. TLS verification and target restrictions remain enforced.
No password or encryption key is printed. A pass is a point-in-time check; the
write workflow repeats interface and rule checks immediately before adding.
For an existing assignment, this command uses that record's stored interface;
for a proposed address without a record, it previews the device default.

## Edit reconciliation and Public IP deletion

An edit saves database configuration, stops polling, clears counters and retains
old rule ownership snapshots. Retry Provisioning uses approval-gated cleanup of
the changed old profile before creating the new exact set. Description-only
changes reuse correct rules. Cleanup/add failures are retryable; router operations
cannot be rolled back atomically and all requested removals are audited first.

Deleting a Public IP saves a durable review before database deletion. With approval
pending, no router connection occurs. Once released, the Public IP deletion view
attempts cleanup; the inventory provides Retry rule cleanup for retained reviews.
Only exact comments, destinations and properties with previously audited created
or verified rule IDs may be removed. Unknown ownership, conflicts, a changed
management IP or a new record using the same old rule set block cleanup. Unrelated
rules are never removed or edited. Device deletion never invokes cleanup, and its
reviews explicitly forbid it even after release.

## Live release remains blocked

`ROUTER_WRITES_RELEASED` remains false, and this change does not enable
`NETSHIELD_RAW_PROVISIONING_ENABLED`. Neither a browser request nor the preflight
command enables writes. Explicit user authorization for the first live test is
required before releasing both gates. No live router test was performed as part
of this implementation. Device deletion remains database-only and preserves
historical rule references without requesting router cleanup.

The add-only, target-scoped command `test_raw_provisioning_once` previews without
network access by default. Its `--apply` mode requires explicit code release, an
exact server-approved target, administrator attribution and matching confirmation
arguments. It never releases global provisioning or cleanup. See
`CONTROLLED_LIVE_TEST.md` for the concrete pending test and prerequisite checks.
