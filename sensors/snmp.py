"""Bounded read-only SNMPv2c adapter. No SET commands or custom BER parser."""
import asyncio
import ipaddress
from types import SimpleNamespace
from django.views.decorators.debug import sensitive_variables
from devices.services.targets import validate_target, TargetPolicyError
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, ContextData, ObjectType, ObjectIdentity,
    UdpTransportTarget, Udp6TransportTarget, bulk_walk_cmd, get_cmd, next_cmd,
)
from pysnmp.proto.rfc1902 import Counter64, Integer32, OctetString, TimeTicks
from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView

UPTIME = "1.3.6.1.2.1.1.3.0"
DESCR = "1.3.6.1.2.1.2.2.1.2"
STATUS = "1.3.6.1.2.1.2.2.1.8"
IN = "1.3.6.1.2.1.31.1.1.1.6"
OUT = "1.3.6.1.2.1.31.1.1.1.10"
CPU = "1.3.6.1.2.1.25.3.3.1.2"
DISCONTINUITY = "1.3.6.1.2.1.31.1.1.1.19"
# MikroTik enterprise table of active PPP/PPPoE sessions. Verified against real devices:
# every binding is <root>.<column>.<session index>, so one row = one active session.
PPP_TABLE = "1.3.6.1.4.1.14988.1.1.14.1.1"
# Column 1 enumerates every session exactly once. Walking the whole table repeats each session
# across all its columns (111,869 bindings / 109 s on a 1,617-session device) for no gain.
PPP_COLUMN = PPP_TABLE + ".1"
# Allow the bulk walker as many round-trips as the column needs; it stops at the table edge.
PPP_MAX_CALLS = 100000
# A real 218-session device returned ~14,283 bindings; keep generous headroom.
PPP_BINDING_LIMIT = 200000
# Larger GETBULK batches cut round-trips. Measured on a 218-session RouterOS device:
# 25 -> 47 s, 40 -> 13 s, 50 -> erratic, 60 -> request rejected. 40 is the safe maximum.
PPP_BULK_REPETITIONS = 40
# RouterOS rejects oversized batches outright; retry once at a conservative size.
PPP_BULK_REPETITIONS_FALLBACK = 25
PPP_WALK_RETRIES = 4
# A PPP table walk can take far longer than a scalar read; it gets its own budget.
PPP_READ_TIMEOUT = 120
PPP_REQUEST_TIMEOUT = 8
PPP_REQUEST_RETRIES = 2
# Interface discovery on a PPPoE server returns one row per session (a real device had 1,704),
# so the ifTable walk needs bulk reads and a far higher ceiling than the old 600-row guard.
INTERFACE_BULK_REPETITIONS = 25
INTERFACE_WALK_LIMIT = 20000


class SNMPError(Exception):
    pass


def number(value, expected, minimum=0, maximum=None):
    if not isinstance(value, expected):
        raise SNMPError("SNMP returned an unsupported or missing metric.")
    result = int(value)
    if result < minimum or (maximum is not None and result > maximum):
        raise SNMPError("SNMP returned an invalid metric value.")
    return result


class Client:
    def __init__(self, host, community, port):
        self.host, self.community, self.port = host, community, port
        self.engine = None

    async def open(self, timeout=2, retries=0):
        self.engine = SnmpEngine()
        transport = Udp6TransportTarget if ipaddress.ip_address(self.host).version == 6 else UdpTransportTarget
        self.transport = await transport.create((self.host, self.port), timeout=timeout, retries=retries)
        self.auth = CommunityData(self.community, mpModel=1)

    async def query(self, oids, walk=False):
        fn = next_cmd if walk else get_cmd
        error, status, _, bindings = await fn(self.engine, self.auth, self.transport, ContextData(),
            *(ObjectType(ObjectIdentity(oid)) for oid in oids), lookupMib=False)
        if error:
            raise SNMPError("No valid SNMP reply. Check reachability, community, port and SNMP access.")
        if status:
            raise SNMPError("The device rejected the SNMP read request.")
        if len(bindings) != len(oids):
            raise SNMPError("Incomplete SNMP response.")
        result = [(tuple(oid), value) for oid, value in bindings]
        if not walk and any(oid != tuple(map(int, requested.split('.'))) for (oid, _), requested in zip(result, oids)):
            raise SNMPError("Unexpected SNMP response identifiers.")
        return result

    async def get(self, *oids):
        return [value for _, value in await self.query(oids)]

    async def walk(self, prefix, limit=600):
        root = tuple(map(int, prefix.split('.')))
        current, result = root, []
        for _ in range(limit):
            oid, value = (await self.query(['.'.join(map(str, current))], walk=True))[0]
            if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)) or oid[:len(root)] != root:
                return result
            if oid <= current or len(oid) != len(root) + 1:
                raise SNMPError("Invalid SNMP table ordering.")
            result.append((oid[-1], value))
            current = oid
        raise SNMPError("SNMP table exceeds the 600-row discovery limit.")

    async def bulk_walk(self, prefix, repetitions=INTERFACE_BULK_REPETITIONS, limit=INTERFACE_WALK_LIMIT):
        """Walk a column with GETBULK instead of one GETNEXT per row.

        A PPPoE server exposes one dynamic interface per connected session - a real device
        returned 1,704 rows, which took 45 s row-by-row and tripped the 600-row guard. Bulk
        requests fetch many rows at once, so the same table is read well within the request
        timeout. `maxCalls` lets the walker make as many round-trips as the table needs.
        """
        root = tuple(map(int, prefix.split('.')))
        result = []
        calls = max(1, limit // max(1, repetitions) + 2)
        async for error, status, _index, values in bulk_walk_cmd(
                self.engine, self.auth, self.transport, ContextData(), 0, repetitions,
                ObjectType(ObjectIdentity(prefix)), lookupMib=False, lexicographicMode=True,
                maxCalls=calls, ignoreNonIncreasingOid=True):
            if status or error:
                raise SNMPError("The device rejected the SNMP read request.")
            if not values:
                break
            for oid, value in values:
                row = tuple(oid)
                if row[:len(root)] != root:
                    return result                # left the subtree: the walk is complete
                if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                    return result
                result.append((row, value))
                if len(result) >= limit:
                    return result[:limit]
        return result[:limit]

    async def uptime(self):
        return number((await self.get(UPTIME))[0], TimeTicks) / 100

    async def interfaces(self):
        # PPPoE servers expose a dynamic interface per session, so this table can be large.
        names = [(row[-1], value) for row, value in await self.bulk_walk(DESCR)]
        states = {row[-1]: value for row, value in await self.bulk_walk(STATUS)}
        result = []
        for index, name in names:
            if not isinstance(name, OctetString):
                raise SNMPError("Invalid interface name returned by SNMP.")
            label = name.asOctets().decode('utf-8', errors='replace')
            if not label or len(label) > 255:
                raise SNMPError("Interface name is empty or too long.")
            state = states.get(index)
            result.append({"index": index, "name": label, "status": {1: "Up", 2: "Down"}.get(int(state) if isinstance(state, Integer32) else 0, "Unknown")})
        return result

    async def pppoe_users(self):
        """Count active PPP/PPPoE sessions in the MikroTik PPP table.

        Only column 1 is walked. It enumerates every session (one row per session), while the
        full table repeats every session across all of its columns: on a real 1,617-session
        device the whole table was 111,869 bindings and took 109 s, whereas column 1 alone
        returned the same count in about 1.3 s. That difference is what made Detect PPPoE
        appear to hang past the read budget.

        An empty (but readable) table counts as zero sessions, which is a real reading. Only an
        unrecoverable SNMP failure raises SNMPError.
        """
        root = tuple(map(int, PPP_COLUMN.split('.')))
        indexes = set()
        bindings = 0
        # Some RouterOS builds reject large GETBULK batches; fall back once, then keep it.
        repetitions = PPP_BULK_REPETITIONS
        degraded = False
        while True:
            advanced = False
            failed = False
            async for error, status, _index, values in bulk_walk_cmd(
                    self.engine, self.auth, self.transport, ContextData(), 0, repetitions,
                    ObjectType(ObjectIdentity(PPP_COLUMN)), lookupMib=False, lexicographicMode=True,
                    maxCalls=PPP_MAX_CALLS, ignoreNonIncreasingOid=True):
                if status:
                    if not degraded and repetitions > PPP_BULK_REPETITIONS_FALLBACK:
                        # This build rejected the batch size: retry with a smaller batch.
                        degraded, repetitions = True, PPP_BULK_REPETITIONS_FALLBACK
                        break
                    raise SNMPError("The device rejected the SNMP read request.")
                if error:
                    failed = True
                    break
                if not values:
                    return len(indexes)        # answered, but the column is exhausted
                for oid, _value in values:
                    row = tuple(oid)
                    if row[:len(root)] != root:
                        return len(indexes)        # left the column: the walk is complete
                    advanced = True
                    bindings += 1
                    if bindings > PPP_BINDING_LIMIT:
                        raise SNMPError("The PPP session table exceeds the discovery limit.")
                    indexes.add(row[len(root):])
            else:
                return len(indexes)                # generator finished cleanly: column exhausted
            if not failed:
                continue                           # progressed or degraded: run again
            if advanced:
                continue                           # timed out mid-column: the retry resumes
            raise SNMPError(
                "The PPP session table could not be read. The device stopped "
                "responding part-way through the SNMP walk.")

            

    async def sample(self, sensor):
        uptime = await self.uptime()
        result = {"uptime_seconds": uptime}
        if sensor.kind == "cpu":
            loads = [number(v, Integer32, maximum=100) for _, v in await self.walk(CPU)]
            if not loads:
                raise SNMPError("The device did not return CPU readings.")
            result['cpu'] = sum(loads) / len(loads)
        elif sensor.kind == "pppoe":
            # A count of zero is a valid reading; None is never produced here.
            result['pppoe_users'] = await self.pppoe_users()
        elif sensor.kind == "traffic":
            suffix = '.' + str(sensor.interface_index)
            name, status, incoming, outgoing, discontinuity = await self.get(*(oid + suffix for oid in (DESCR, STATUS, IN, OUT, DISCONTINUITY)))
            if not isinstance(name, OctetString) or name.asOctets().decode('utf-8', errors='replace') != sensor.interface_name:
                raise SNMPError("Interface identity changed. Rediscover interfaces and add a replacement sensor.")
            result.update(interface_status={1: "Up", 2: "Down"}.get(number(status, Integer32), "Unknown"),
                          in_octets=number(incoming, Counter64, maximum=2**64-1),
                          out_octets=number(outgoing, Counter64, maximum=2**64-1),
                          discontinuity=number(discontinuity, TimeTicks) if isinstance(discontinuity, TimeTicks) else None)
        return result


@sensitive_variables()
def read(device, community, port, operation, sensor=None):
    if not device.enabled or device.device_type != 'mikrotik':
        raise SNMPError("Enable a saved MikroTik device before using SNMP sensors.")
    try:
        validate_target(SimpleNamespace(pk=device.pk, management_ip=device.management_ip, api_port=port))
    except TargetPolicyError as error:
        raise SNMPError(str(error)) from None

    async def execute():
        client = Client(device.management_ip, community, port)
        try:
            # A PPP table walk is long-running and reads a busy device, so it gets a
            # longer per-request timeout and a larger overall budget than scalar reads.
            is_pppoe = operation == 'sample' and getattr(sensor, 'kind', None) == 'pppoe'
            await client.open(timeout=PPP_REQUEST_TIMEOUT if is_pppoe else 2,
                              retries=PPP_REQUEST_RETRIES if is_pppoe else 0)
            if operation == 'interfaces':
                return await client.interfaces()
            if operation == 'test':
                return await client.uptime()
            return await client.sample(sensor)
        finally:
            if client.engine:
                client.engine.close_dispatcher()
    budget = PPP_READ_TIMEOUT if operation == 'sample' and getattr(sensor, 'kind', None) == 'pppoe' else 20
    try:
        return asyncio.run(asyncio.wait_for(execute(), timeout=budget))
    except SNMPError:
        raise
    except TimeoutError:
        raise SNMPError("SNMP read timed out.") from None
    except Exception:
        # Library exceptions may contain community strings. Never expose them.
        raise SNMPError("SNMP read failed. Check device SNMP access and configuration.") from None
