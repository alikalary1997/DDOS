"""Interface discovery must handle PPPoE servers, which expose one interface per session.

The old walk used one GETNEXT per row and gave up at 600 rows, which a real PPPoE server
(1,704 dynamic interfaces) blew past after 45 seconds. These tests pin the replacement:
a bulk walk that spans every batch, stops cleanly at the subtree edge, and raises rather
than silently returning a short list.
"""
import asyncio
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from sensors import snmp
from sensors.snmp import Client, SNMPError

ROOT = tuple(map(int, snmp.DESCR.split(".")))
STATUS_ROOT = tuple(map(int, snmp.STATUS.split(".")))


def fake_client():
    """A Client with a stub engine/auth/transport; only the walk loop is exercised."""
    client = Client.__new__(Client)
    client.engine = MagicMock()
    client.auth = MagicMock()
    client.transport = MagicMock()
    return client


def responder_for(payloads):
    """One bulk walk generator that yields each payload in turn, then an empty batch."""
    def responder(*args, **kwargs):
        async def stream():
            for payload in payloads:
                yield None, 0, 0, payload
        return stream()

    state = {"n": len(payloads)}
    return responder, state


class BulkWalkTests(SimpleTestCase):
    def walk(self, responder, prefix=snmp.DESCR, **kwargs):
        client = fake_client()
        with patch("sensors.snmp.bulk_walk_cmd", new=responder):
            return asyncio.run(client.bulk_walk(prefix, **kwargs))

    def test_every_batch_is_read_until_the_table_ends(self):
        batch1 = tuple((ROOT + (i,), snmp.OctetString(f"if{i}")) for i in range(1, 26))
        batch2 = tuple((ROOT + (i,), snmp.OctetString(f"if{i}")) for i in range(26, 51))
        responder, state = responder_for([batch1, batch2, ()])
        result = self.walk(responder, repetitions=25, limit=500)
        self.assertEqual(len(result), 50, "both batches are kept, not just the first")
        self.assertGreaterEqual(state["n"], 3, "the walk supplied every batch plus an empty one")

    def test_the_limit_allows_far_more_than_the_old_600_rows(self):
        # A real PPPoE server exposed 1,704 interfaces; the ceiling must clear that easily.
        self.assertGreaterEqual(snmp.INTERFACE_WALK_LIMIT, 5000)
        rows = tuple((ROOT + (i,), snmp.OctetString(f"if{i}")) for i in range(1, 1001))
        responder, _state = responder_for([rows, ()])
        result = self.walk(responder, repetitions=500, limit=snmp.INTERFACE_WALK_LIMIT)
        self.assertEqual(len(result), 1000, "a 1000-row table is read in full")

    def test_the_walk_stops_when_it_leaves_the_subtree(self):
        inside = tuple((ROOT + (i,), snmp.OctetString(f"if{i}")) for i in (1, 2))
        outside = ((STATUS_ROOT + (1,), snmp.Integer32(1)),)
        responder, _state = responder_for([inside, outside])
        result = self.walk(responder, repetitions=2, limit=500)
        self.assertEqual(len(result), 2, "rows outside the column are discarded")
        self.assertTrue(all(row[:len(ROOT)] == ROOT for row, _value in result))

    def test_a_rejected_request_raises_instead_of_returning_a_short_list(self):
        def refused(*args, **kwargs):
            async def stream():
                yield None, 2, 0, ()          # status set: the device refused the read
            return stream()

        with self.assertRaises(SNMPError):
            self.walk(refused)

    def test_an_empty_table_returns_no_rows_rather_than_an_error(self):
        responder, _state = responder_for([()])
        self.assertEqual(self.walk(responder), [])


class InterfaceListTests(SimpleTestCase):
    def test_names_and_states_are_paired_by_index(self):
        names = tuple((ROOT + (i,), snmp.OctetString(name))
                      for i, name in ((1, "lo"), (2, "ether13"), (3, "sfp-sfpplus1")))
        states = tuple((STATUS_ROOT + (i,), snmp.Integer32(state))
                       for i, state in ((1, 1), (2, 2), (3, 1)))

        # interfaces() walks the description column first, then the status column.
        payloads = [[names, ()], [states]]
        calls = {"n": 0}

        def responder(*args, **kwargs):
            batch = payloads[min(calls["n"], len(payloads) - 1)]
            calls["n"] += 1

            async def stream():
                for payload in batch:
                    yield None, 0, 0, payload
            return stream()

        client = fake_client()
        with patch("sensors.snmp.bulk_walk_cmd", new=responder):
            result = asyncio.run(client.interfaces())

        self.assertEqual([row["name"] for row in result], ["lo", "ether13", "sfp-sfpplus1"])
        self.assertEqual([row["status"] for row in result], ["Up", "Down", "Up"])
        self.assertEqual([row["index"] for row in result], [1, 2, 3])
