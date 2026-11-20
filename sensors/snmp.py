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
# IF-MIB administrative state: 1 = up (not disabled), 2 = down (shut by an operator).
ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
# ifHighSpeed is Mbps; ifSpeed is bits/s and saturates at 4.29 G on old agents.
HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
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
# Neighbour discovery, for switches. Both tables describe one remote device per row. Walking a
# table ROOT returns every column for every row (387 bindings for 43 neighbours on a real
# switch), so only a single column is walked - the one that has exactly one entry per row:
#   LLDP  lldpRemTable   .1.0.8802.1.1.2.1.4.1.1.<column>.<timeMark>.<localPort>.<index>
#         column 4 = lldpRemChassisIdSubtype, present on every row
#   CDP   cdpCacheTable  .1.3.6.1.9.9.23.1.2.1.1.<column>.<ifIndex>.<deviceIndex>
#         column 1 = cdpCacheAddressType, present on every row
LLDP_NEIGHBOR_COLUMN = "1.0.8802.1.1.2.1.4.1.1.4"
# lldpLocPortTable: maps an LLDP local port number to the local interface's own name.
# The remote table's `localPort` number is NOT the interface ifIndex (a real switch had 1..43
# against ifIndexes of 10101+), so this table is what joins the two.
LLDP_LOCAL_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
CDP_NEIGHBOR_COLUMN = "1.3.6.1.9.9.23.1.2.1.1.1"
# cdpCacheTable's own root. CDP_NEIGHBOR_COLUMN above points at column 1 (used for counting),
# so per-port reads append the column to this instead of chopping the last arc off that OID -
# doing the latter produced <table>.1.<column>, an OID the switch does not have.
CDP_TABLE_ROOT = "1.3.6.1.9.9.23.1.2.1.1"
NEIGHBOR_WALK_LIMIT = 5000
# Device types this adapter accepts: both speak SNMPv2c for the counters it reads.
SNMP_DEVICE_TYPES = ("mikrotik", "cisco")


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

        Some agents (a real Cisco switch does this intermittently) reject a bulk read with a
        GETBULK status error while a single GETNEXT from the same OID answers fine, so a
        refused bulk walk falls back to GETNEXT instead of reporting an empty table. An empty
        result therefore means "the agent says this column has no rows", not "we gave up".
        """
        root = tuple(map(int, prefix.split('.')))
        result = []
        calls = max(1, limit // max(1, repetitions) + 2)
        try:
            async for error, status, _index, values in bulk_walk_cmd(
                    self.engine, self.auth, self.transport, ContextData(), 0, repetitions,
                    ObjectType(ObjectIdentity(prefix)), lookupMib=False, lexicographicMode=True,
                    maxCalls=calls, ignoreNonIncreasingOid=True):
                if status:
                    # The device answered and refused the read: not an empty table, and not a
                    # stall that a row-by-row retry could rescue. Surface it as a failure.
                    raise SNMPError("The device rejected the SNMP read request.")
                if error:
                    # A timeout part-way through is NOT an empty table. Returning what was
                    # collected so far would report a truncated (often empty) column as the
                    # truth, which is how every CDP neighbour silently disappeared.
                    raise SNMPError("The device stopped responding part-way through the SNMP walk.")
                if not values:
                    break                           # the agent says the column is exhausted
                for oid, value in values:
                    row = tuple(oid)
                    if row[:len(root)] != root:
                        return result            # left the subtree: the walk is complete
                    if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                        return result
                    result.append((row, value))
                    if len(result) >= limit:
                        return result[:limit]
            return result[:limit]
        except SNMPError as error:
            if str(error).startswith("The device rejected"):
                raise
            # The agent stopped answering mid-table. Returning what was collected so far
            # reports a truncated (often empty) column as the truth - that is how every CDP
            # neighbour silently disappeared - so the walk is resumed row by row instead.
            return await self._getnext_walk(root, result, limit)

    async def _getnext_walk(self, root, collected, limit):
        """Continue a walk row-by-row after a bulk walk failed, resuming from `collected`.

        Single GETNEXT requests are cheap and never batched, so a loaded agent that chokes on
        a 25-row GETBULK still answers them. This is the fallback that keeps neighbours (and
        interface tables) readable on a busy switch.
        """
        result = list(collected)
        current = result[-1][0] if result else root
        while len(result) < limit:
            oid, value = (await self.query(['.'.join(map(str, current))], walk=True))[0]
            if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)) or oid[:len(root)] != root:
                return result
            if oid <= current:
                raise SNMPError("Invalid SNMP table ordering.")
            result.append((oid, value))
            current = oid
        return result

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

    async def ports(self):
        """Every interface with its operational and administrative state, for a switch panel.

        A port row is: index, name, oper status, admin status, speed, alias. `oper` is the
        link state (1 up / 2 down); `admin` distinguishes a shut port from a disconnected
        cable, which is the difference between "disabled" and "not connected".
        """
        names = {row[-1]: value for row, value in await self.bulk_walk(DESCR)}
        oper = {row[-1]: value for row, value in await self.bulk_walk(STATUS)}
        admin = {row[-1]: value for row, value in await self.bulk_walk(ADMIN_STATUS)}
        speed = {row[-1]: value for row, value in await self.bulk_walk(SPEED)}
        result = []
        for index, name in sorted(names.items()):
            if not isinstance(name, OctetString):
                continue
            label = name.asOctets().decode('utf-8', errors='replace')
            if not label or len(label) > 255:
                continue
            oper_state = number(oper[index], Integer32) if isinstance(oper.get(index), Integer32) else 0
            admin_state = number(admin[index], Integer32) if isinstance(admin.get(index), Integer32) else 0
            mbps = 0
            if isinstance(speed.get(index), Integer32):
                mbps = int(speed[index]) // 1_000_000
            result.append({
                "index": index, "name": label,
                "oper": {1: "up", 2: "down"}.get(oper_state, "unknown"),
                "admin": {1: "up", 2: "down"}.get(admin_state, "unknown"),
                "speed_mbps": mbps,
                "alias": "",
            })
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

            

    async def neighbors(self):
        """How many neighbours this switch currently sees through LLDP, else CDP.

        Cisco switches may expose both tables, in which case LLDP is used and CDP ignored: the
        two would describe the same links twice. An empty but readable table is a real 0.
        """
        for column in (LLDP_NEIGHBOR_COLUMN, CDP_NEIGHBOR_COLUMN):
            root = tuple(map(int, column.split('.')))
            rows = {row[len(root):] for row, _value in await self.bulk_walk(column, limit=NEIGHBOR_WALK_LIMIT)}
            if rows:
                return len(rows)
        return 0

    @staticmethod
    def _looks_like_text(values):
        """True when most values read as ordinary text rather than binary.

        A raw MAC address decodes to a few printable bytes plus escape characters, so the
        test demands that most characters be letters, digits or common punctuation. A
        minority of odd values is tolerated: platform strings on real devices carry
        non-ASCII bytes that a strict per-value check would reject outright.
        """
        sampled = [value for value in values if value]
        if len(sampled) < max(1, len(values) // 2):
            return False
        good = 0
        for value in sampled:
            chars = len(value)
            alnum = sum(1 for ch in value if ch.isalnum() or ch in '-_.@/: ()')
            if chars and alnum / chars > 0.85:
                good += 1
        return good / len(values) > 0.7

    async def neighbors_by_port(self):
        """Neighbours seen per local port, for the switch panel.

        Returns {local port name: [{name, port, platform, protocol}, ...]}, where the port name is
        the switch's own interface name (GigabitEthernet0/21). Both protocols are read: a port can
        have a neighbour that only speaks CDP (a LiteBeam radio, for instance), and reading
        LLDP alone left those ports looking empty in the app.

        The two tables index ports very differently, so each is joined to a port name first:
          LLDP  index <timeMark>.<localPort>.<index>, where localPort is LLDP's own 1..N
                numbering - translated to a name through lldpLocPortTable's port descr.
          CDP   index <ifIndex>.<deviceIndex>, where ifIndex IS the interface index - which is
                the same key ifDescr (the port name table) is indexed by.
        Column numbers vary between agent builds (on a real Cisco switch the LLDP neighbour
        name sat in column 9, the remote port in 7, while CDP used 6 and 7), so columns are
        identified by what they contain, not by their position.
        """
        by_port = {}
        # LLDP first: for ports where it holds a real device name it is the richer source.
        # CDP is merged after, so a port whose LLDP entry is blank (a LiteBeam radio that only
        # fills in the chassis/port columns, showing up as an unnamed "eth0") gets its real
        # identity from CDP instead of staying "Unknown device".
        for name, neighbour in await self._lldp_neighbors_by_port():
            by_port.setdefault(name, []).append(neighbour)
        for name, neighbour in await self._cdp_neighbors_by_port():
            entries = by_port.setdefault(name, [])
            blank = next((e for e in entries if e["protocol"] == "LLDP" and not e["name"]), None)
            if blank is not None:
                entries.remove(blank)
            entries.append(neighbour)
        for entries in by_port.values():
            entries.sort(key=lambda item: (item["name"].lower(), item["port"].lower()))
        return by_port

    async def _walk_with_retry(self, prefix, attempts=3):
        """bulk_walk, retrying an empty or refused column with progressively gentler batching.

        A busy switch drops a 25-row GETBULK batch part-way through a table walk (a real
        Cisco switch times out mid-CDP-table while its sensors are being polled), yet answers
        the same walk in 5-row batches. Each retry halves the batch size, and the final one
        drops to single GETNEXT requests, so a loaded agent still yields its table.
        """
        for attempt in range(attempts):
            repetitions = max(1, INTERFACE_BULK_REPETITIONS >> attempt)
            try:
                rows = await self.bulk_walk(prefix, repetitions=repetitions, limit=NEIGHBOR_WALK_LIMIT)
            except SNMPError:
                rows = []
            if rows:
                return rows
        return []

    async def _port_names_by_index(self):
        """ifIndex -> interface name, the join CDP needs (its index is the ifIndex)."""
        names = {}
        try:
            for oid, value in await self.bulk_walk(DESCR, limit=NEIGHBOR_WALK_LIMIT):
                if isinstance(value, OctetString):
                    names[tuple(oid)[-1]] = value.asOctets().decode('utf-8', 'replace').strip()
        except SNMPError:
            return {}
        return names

    async def _lldp_neighbors_by_port(self):
        """[(port name, neighbour)] from the LLDP remote table."""
        base = LLDP_NEIGHBOR_COLUMN.rsplit('.', 1)[0]
        root = tuple(map(int, base.split('.')))

        def text(value):
            return value.asOctets().decode('utf-8', 'replace').strip() if isinstance(value, OctetString) else ''

        # localPort number -> port name, so neighbours can be attached to a real port.
        local_root = tuple(map(int, LLDP_LOCAL_PORT_ID.split('.')))
        local_ports = {}
        try:
            for oid, value in await self.bulk_walk(LLDP_LOCAL_PORT_ID, limit=NEIGHBOR_WALK_LIMIT):
                # This column's OID already ends in .3, so the trailing number IS the local port.
                index = tuple(oid)[len(local_root):]
                if len(index) == 1 and isinstance(value, OctetString):
                    local_ports[index[0]] = text(value)
        except SNMPError:
            local_ports = {}
        if not local_ports:
            return []

        table = {}
        for column in range(5, 13):
            try:
                rows = await self.bulk_walk(f"{base}.{column}", limit=NEIGHBOR_WALK_LIMIT)
            except SNMPError:
                continue                      # some builds refuse particular columns
            for oid, value in rows:
                # Index is <column>.<timeMark>.<localPort>.<entry>: the leading column number is
                # part of the reported index on this agent, so it is dropped explicitly.
                index = tuple(oid)[len(root) + 1:]
                if len(index) == 3:
                    table.setdefault(index, {})[column] = text(value)
        if not table:
            return []

        columns = {col: [row.get(col, '') for row in table.values()] for col in range(5, 13)}
        name_col = next((col for col in (9, 5, 6, 8) if self._looks_like_text(columns.get(col, []))), None)
        port_col = next((col for col in (7, 8, 6) if col != name_col and self._looks_like_text(columns.get(col, []))), None)
        platform_col = next((col for col in (10, 11, 12) if self._looks_like_text(columns.get(col, []))), None)

        result = []
        for index, row in table.items():
            _time_mark, local_port, _entry = index
            interface = local_ports.get(local_port)
            if not interface:
                continue                      # cannot attribute it to a real port
            neighbour = {
                "name": row.get(name_col, "") if name_col else "",
                "port": row.get(port_col, "") if port_col else "",
                "platform": row.get(platform_col, "") if platform_col else "",
                "protocol": "LLDP",
            }
            if any(neighbour.values()):
                result.append((interface, neighbour))
        return result

    async def _cdp_neighbors_by_port(self):
        """[(port name, neighbour)] from the Cisco CDP cache table.

        The cache is indexed by the local interface's ifIndex, which is not the port's LLDP
        number, so names come from ifDescr keyed by the same ifIndex. One row per neighbour;
        the device index inside the index may be a plain number or "<address>.<n>", which is
        why only the first element is used.
        """
        base = CDP_TABLE_ROOT
        root = tuple(map(int, base.split('.')))

        def text(value):
            return value.asOctets().decode('utf-8', 'replace').strip() if isinstance(value, OctetString) else ''

        names = await self._port_names_by_index()
        if not names:
            return []

        # cdpCacheDeviceId / cdpCacheDevicePort / cdpCachePlatform are 6 / 7 / 8 in the MIB, but
        # this agent intermittently refuses a whole column (a real switch returned 0 rows for 1
        # and 2, then answered 6-8 a moment later), so each column is retried once before it is
        # treated as genuinely empty.
        table = {}
        for column in (6, 7, 8):
            rows = await self._walk_with_retry(f"{base}.{column}")
            for oid, value in rows:
                # Index is <ifIndex>.<deviceIndex> straight after the table root, since the
                # column is already part of the walked OID.
                index = tuple(oid)[len(root):]
                if index:
                    table.setdefault(index[0], {})[column] = text(value)
        if not table:
            return []

        columns = {col: [row.get(col, '') for row in table.values()] for col in (6, 7, 8)}
        name_col = next((col for col in (6, 7, 8) if self._looks_like_text(columns.get(col, []))), None)
        port_col = next((col for col in (7, 8, 6) if col != name_col and self._looks_like_text(columns.get(col, []))), None)
        platform_col = next((col for col in (8, 7, 6) if col not in (name_col, port_col) and self._looks_like_text(columns.get(col, []))), None)

        result = []
        for if_index, row in table.items():
            interface = names.get(if_index)
            if not interface:
                continue
            neighbour = {
                "name": row.get(name_col, "") if name_col else "",
                "port": row.get(port_col, "") if port_col else "",
                "platform": row.get(platform_col, "") if platform_col else "",
                "protocol": "CDP",
            }
            # Some agents (RouterOS does this) publish a placeholder row whose every column is
            # empty. It describes no neighbour, so it is dropped rather than listed nameless.
            if neighbour["name"] or neighbour["port"] or neighbour["platform"]:
                result.append((interface, neighbour))
        return result

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
        elif sensor.kind == "neighbors":
            # Same rule as PPPoE: a real empty table is 0, a failed read raises.
            result['neighbor_count'] = await self.neighbors()
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
    if not device.enabled or device.device_type not in SNMP_DEVICE_TYPES:
        raise SNMPError("Enable a saved MikroTik or Cisco device before using SNMP sensors.")
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
            if operation == 'ports':
                return await client.ports()
            if operation == 'neighbors':
                return await client.neighbors_by_port()
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
