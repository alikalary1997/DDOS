# SNMP sensors

This subsystem is independent of RouterOS API credentials, RAW rules, public-IP
assignments, RAW polling and detection. It uses PySNMP 7.1.30 SNMPv2c GET and
GETNEXT only. No SET, router configuration, firewall writes or counter resets exist
in the sensor adapter. The existing management-address policy is applied to the
saved device IP and SNMP port.

## Setup

Devices → Inspect → Add Sensor (also available in the Actions menu).

1. Enter an SNMP community and port (161 by default). Test SNMP & save credentials
   makes an explicit, bounded uptime read, then encrypts the community using the
   existing `NETSHIELD_DEVICE_ENCRYPTION_KEY` service. Communities never appear in
   HTML, JSON, logs or serialized model exports. A read-only community should be
   configured on the device by its administrator; this app never configures SNMP.
   SNMPv2c sends its community unencrypted on the wire.
2. Select Traffic, Uptime or CPU. Traffic discovery displays Up/Down interface
   status and accepts multiple interfaces. Discovered selections are signed,
   bound to the administrator, device IP and credential revision, and expire after
   ten minutes. Duplicate sensors are preserved, not recreated or restarted.
3. Adding a new sensor starts read-only polling automatically. Existing duplicate
   sensors retain their current state. Use Start to resume an existing stopped
   sensor. Rename or change its polling interval through Edit. Changing a traffic
   interface requires adding a replacement sensor so history retains its identity.

## Automatic worker lifecycle

An administrator's Add or Start action enables only the selected sensors and
opens the separate SNMP polling gate. NetShield starts a hidden worker using the
application's Python interpreter, or reuses the existing worker. Startup and worker
OS locks prevent overlapping launches and polling processes. Opening a page,
restarting Django or testing credentials does not itself start polling.

CPU and uptime require one successful sample; bandwidth needs two counter samples.
The UI says Waiting for data until readings exist. Launch failures retain the
sensor, stop it and show an error. Press Start to retry. Worker output is recorded
in `runtime/snmp/worker.log`.

Stop in the UI retains history and excludes that sensor from subsequent polls.
An in-flight read may finish (bounded to 20 seconds), but its result is discarded
if the sensor was stopped, edited or deleted. To stop all sensors and the worker:

```powershell
.\venv\Scripts\python.exe manage.py sensor_polling_gate --disable
```

The gate remains an operational shutdown control; a subsequent explicit Add/Start
can authorize polling again. The worker can also be run manually with
`python manage.py poll_sensors` when authorized, with safe Ctrl+C shutdown.
Deployment assumes one application host/shared database; multiple hosts need a
distributed lock. RAW workers, their gates and firewall rules are unaffected.

## Readings and history

Polling is sequential, with no overlapping cycles. Each interval is loaded from
the database; edits apply on the next scheduling pass. A sensor waits its interval
after the previous read finishes. Bandwidth uses Python integer counter deltas,
actual monotonic elapsed time and decimal Mbps (1,000,000 bits/second). Exact
unsigned Counter64 values are stored as strings because SQLite numeric affinity
rounds large unsigned integers.

First traffic readings, failures, changes, long gaps, uptime resets, counter
decreases and interface discontinuities establish a new baseline, never invented
zero rates. `ifCounterDiscontinuityTime` is checked where supported. Decreases
without a discontinuity object are treated as resets, rather than guessed wraps.
CPU is the average of the returned valid core loads. Uptime decreases record
restart indications, except the expected 32-bit TimeTicks wrap. A sysUpTime reset
can also indicate an SNMP-agent restart; it is not definitive proof of an OS reboot.

History remains in `SensorSample` until its sensor/device is explicitly deleted.
The API and graphs show the latest 120 samples; graph spacing uses actual sample
timestamps and breaks on missing readings. Browser refresh runs every five
seconds and only reads database history. Stopped/stale/failed data is visibly
labeled and is never represented as live traffic. No sample retention job is
enabled; plan retention before a large long-running deployment.

## Reference script review

The entire supplied Tkinter script was read before implementation. Its uptime,
interface discovery, per-core CPU averaging, Counter64 reads and rate formatting
informed this implementation. Its desktop UI and handwritten BER encoder/decoder
were not copied. PySNMP handles protocol parsing and response correlation; the
adapter additionally validates returned OIDs, ASN.1 metric types, value ranges,
increasing table OIDs, row limits, deadlines and transport cleanup. It supports
IPv4 and IPv6 saved management addresses. Unlike the reference, per-sensor polling
does not spawn an unbounded set of threads, and a failed sample clears the rate
baseline rather than stretching rates across gaps.

Tests: `python manage.py test sensors` and `node --test sensors/tests/sensors.test.cjs`.
All automated tests use mocked device responses; they do not contact MikroTik.
