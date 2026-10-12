# Detection-only engine

Passive detection is enabled by default for all existing and future public IP
assignments on enabled MikroTik devices. Each assignment can opt out through its
administrator-only Enable/Disable detection control. Detection consumes persisted
FirewallSample updates; it never starts polling or contacts a router. Monitoring
must still be explicitly authorized using the existing single-worker scope.
Global thresholds and confirmation/recovery settings are re-read for every sample.
The deployment migration enables the global gate once without overwriting those
settings or incident history. Restarts never reset administrator preferences.

Settings → DDoS Detection contains all eight thresholds, entry confirmation count,
recovery count, and recovery hysteresis. Defaults are three samples in each
direction and 20% hysteresis. These thresholds remain illustrative, not validated
production values. Entry comparisons are inclusive (`>=`). Recovery comparisons
are strict (`< threshold × (1 − hysteresis/100)`) across all four metrics.
An Attack downgrades to Warning after confirmed attack recovery, and to Normal
only after confirmed warning recovery. Warning-to-Attack escalation needs its own
consecutive attack samples. A zero Warning threshold therefore never recovers
below zero; choose positive thresholds when a zero-traffic recovery is desired.

Samples must match the saved assignment/profile, have a fresh aware timestamp and
four finite nonnegative rates. The saved polling interval plus the existing
freshness grace defines gaps; no polling interval is hardcoded. Replayed timestamps
are ignored, while invalid samples and gaps reset confirmation counts. Initial
above-threshold samples show Unknown until confirmed; a previously confirmed
state remains until escalation/recovery is confirmed. Missing/stopped/stale data
always projects Unknown, independently of monitoring health.

One event spans Warning, escalation and recovery. Its start includes the first
sample in the confirmed sequence. Peaks include that sequence, and all subsequent
valid observations. Event links use SET_NULL and retain immutable address/device
snapshots. Missing monitoring, deletion or reassignment never fabricates recovery:
the old event remains open/unresolved with its last observation timestamp.
Duration is end minus start for closed events and elapsed wall time for open ones.
The authenticated DDoS Detection page provides paginated history.

## Operational controls

On Public IP Monitoring, administrators can disable or enable passive detection
for an individual assignment. This does not alter monitoring, provisioning, RAW
rules or the assignment profile. Disabled/stopped/stale assignments show Unknown.
Opt-outs survive edits and restarts. Re-enabling resets confirmation counts and
waits for new real samples; it does not replay cached traffic or duplicate history.

The optional server-wide kill switch is:

```powershell
.\venv\Scripts\python.exe manage.py detection_control --disable
.\venv\Scripts\python.exe manage.py detection_control --enable
```

These commands never start or stop polling; global enable preserves per-IP opt-outs.
There is no Company-only or assignment allowlist in detection. Polling's original
strict device/assignment/address scope, singleton lock, and stop controls remain.
When deploying new code, reload only an already-authorized running worker, preserving
its exact scope. New devices/IPs are never polled automatically.

Automated tests use isolated fixtures. No test traffic is generated on real devices.
