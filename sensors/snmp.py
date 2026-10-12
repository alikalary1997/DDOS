"""Bounded read-only SNMPv2c adapter. No SET commands or custom BER parser."""
import asyncio
import ipaddress
from types import SimpleNamespace
from django.views.decorators.debug import sensitive_variables
from devices.services.targets import validate_target, TargetPolicyError
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, ContextData, ObjectType, ObjectIdentity,
    UdpTransportTarget, Udp6TransportTarget, get_cmd, next_cmd,
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

    async def open(self):
        self.engine = SnmpEngine()
        transport = Udp6TransportTarget if ipaddress.ip_address(self.host).version == 6 else UdpTransportTarget
        self.transport = await transport.create((self.host, self.port), timeout=2, retries=0)
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

    async def uptime(self):
        return number((await self.get(UPTIME))[0], TimeTicks) / 100

    async def interfaces(self):
        names = await self.walk(DESCR)
        states = dict(await self.walk(STATUS))
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

    async def sample(self, sensor):
        uptime = await self.uptime()
        result = {"uptime_seconds": uptime}
        if sensor.kind == "cpu":
            loads = [number(v, Integer32, maximum=100) for _, v in await self.walk(CPU)]
            if not loads:
                raise SNMPError("The device did not return CPU readings.")
            result['cpu'] = sum(loads) / len(loads)
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
            await client.open()
            if operation == 'interfaces':
                return await client.interfaces()
            if operation == 'test':
                return await client.uptime()
            return await client.sample(sensor)
        finally:
            if client.engine:
                client.engine.close_dispatcher()
    try:
        return asyncio.run(asyncio.wait_for(execute(), timeout=20))
    except SNMPError:
        raise
    except TimeoutError:
        raise SNMPError("SNMP read timed out.") from None
    except Exception:
        # Library exceptions may contain community strings. Never expose them.
        raise SNMPError("SNMP read failed. Check device SNMP access and configuration.") from None
