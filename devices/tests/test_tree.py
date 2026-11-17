"""Groups (nested, group-only) and the device topology chain are two independent features."""
import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from devices.models import Device, Group, tree_summary
from devices.services.credentials import encrypt_password
from devices.services.topology import build_topology, topology_summary
from devices.services.tree_view import build_tree


class Base(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="chain-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.counter = 0

    def device(self, name, parent=None, group=None):
        self.counter += 1
        device = Device(name=name, management_ip=f"10.20.30.{self.counter}", username="api-user",
                        encrypted_password=encrypt_password(secrets.token_urlsafe(12)))
        device.save()                       # needs a pk to be a parent
        if parent is not None:
            device.set_topology_parent(parent)
        device.group = group
        device.save()
        return device

    def group(self, name, parent=None):
        group = Group(name=name)
        group.save()
        group.set_parent(parent)
        group.save()
        return group

    def rows(self, rows):
        found = {}
        for row in rows:
            found[row["name"]] = row
            found.update(self.rows(row["children"]))
        return found


class TopologyChainTests(Base):
    def test_topology_parent_is_a_device_and_chain_renders_at_variable_depth(self):
        # NCS -> Limit-4 -> Kalar -> Tower, and a tower attached straight to Limit-4.
        ncs = self.device("NCS")
        limit = self.device("Limit-4", ncs)
        pppoe = self.device("Kalar", limit)
        tower = self.device("Tower-1", pppoe)
        short_tower = self.device("Tower-9", limit)      # skips the PPPoE-server level

        rows = self.rows(build_topology())
        self.assertEqual(rows["NCS"]["depth"], 0)
        self.assertEqual(rows["Limit-4"]["depth"], 1)
        self.assertEqual(rows["Kalar"]["depth"], 2)
        self.assertEqual(rows["Tower-1"]["depth"], 3)
        self.assertEqual(rows["Tower-9"]["depth"], 2)     # directly under the Limit
        self.assertEqual({c["name"] for c in rows["Limit-4"]["children"]}, {"Kalar", "Tower-9"})
        self.assertEqual(topology_summary(), {"devices": 5, "depth": 4})
        self.assertEqual([r["name"] for r in build_topology()], ["NCS"])

    def test_cycle_prevention_rejects_a_loop(self):
        ncs = self.device("NCS")
        limit = self.device("Limit-1", ncs)
        tower = self.device("Tower-1", limit)
        with self.assertRaises(ValidationError):
            ncs.set_topology_parent(limit)          # its own child
        with self.assertRaises(ValidationError):
            limit.set_topology_parent(tower)        # its own descendant
        with self.assertRaises(ValidationError):
            limit.set_topology_parent(limit)        # itself
        # A group is never a valid topology parent.
        with self.assertRaises(ValidationError):
            limit.set_topology_parent(self.group("NotADevice"))

    def test_edit_form_hides_impossible_topology_parents(self):
        ncs = self.device("NCS")
        limit = self.device("Limit-1", ncs)
        tower = self.device("Tower-1", limit)
        page = self.client.get(reverse("device_edit", args=[limit.pk])).content.decode()
        picker = page.split('name="edit-topology_parent"')[1].split("</select>")[0]
        self.assertNotIn(f'value="d:{limit.pk}"', picker)   # itself
        self.assertNotIn(f'value="d:{tower.pk}"', picker)   # its own descendant
        self.assertIn(f'value="d:{ncs.pk}"', picker)        # its current parent stays

    def test_edit_form_rejects_a_submitted_loop(self):
        ncs = self.device("NCS")
        limit = self.device("Limit-1", ncs)
        tower = self.device("Tower-1", limit)
        payload = {
            "edit-name": limit.name, "edit-management_ip": str(limit.management_ip),
            "edit-device_type": limit.device_type, "edit-api_port": limit.api_port,
            "edit-use_ssl": "true", "edit-username": limit.username, "edit-password": "",
            "edit-incoming_monitoring_interface": "", "edit-description": "", "edit-group": "",
            "edit-topology_parent": f"d:{tower.pk}",
        }
        response = self.client.post(reverse("device_edit", args=[limit.pk]), payload,
                                    HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 400)
        limit.refresh_from_db()
        self.assertEqual(limit.topology_parent_id, ncs.pk)   # unchanged

    def test_topology_view_renders(self):
        ncs = self.device("NCS")
        self.device("Limit-1", ncs)
        response = self.client.get(reverse("device_topology"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["topology_summary"], {"devices": 2, "depth": 2})


class GroupNestingTests(Base):
    def test_groups_nest_only_under_groups(self):
        parent = self.group("Limit")
        child = self.group("Kalar", parent)
        self.assertEqual(child.parent_id, parent.pk)
        with self.assertRaises(ValidationError):
            child.set_parent(self.device("NotAGroup"))

    def test_group_parent_picker_never_offers_a_device(self):
        self.device("NCS")
        self.group("Limit")
        page = self.client.get(reverse("device_tree")).content.decode()
        # The reference's group form asks only for a name, so no parent picker is rendered here.
        self.assertNotIn('name="parent"', page)
        # The sidebar (and its "+ Group" control) is rendered client-side from the JSON payload.
        self.assertIn('id="ref-sidebar"', page)
        self.assertIn('ref_groups.js', page)
        # Nesting still cannot involve a device: the model refuses it outright.
        with self.assertRaises(ValidationError):
            self.group("Nested").set_parent(self.device("A-Device"))
        # The device edit form's group picker is groups-only too.
        edit = self.client.get(reverse("device_edit", args=[Device.objects.first().pk])).content.decode()
        group_picker = edit.split('name="edit-group"')[1].split("</select>")[0]
        self.assertNotIn('value="d:', group_picker)

    def test_recursive_group_and_device_counts(self):
        root = self.group("Root")
        mid = self.group("Mid", root)
        leaf = self.group("Leaf", mid)
        side = self.group("Side", root)
        # Devices tagged into different depths (tag only, unrelated to topology).
        self.device("A", group=root)
        self.device("B", group=mid)
        self.device("C", group=leaf)
        self.device("D", group=side)
        self.device("Untagged")
        rows = self.rows(build_tree())
        self.assertEqual(rows["Root"]["group_count"], 3)     # Mid, Leaf, Side
        self.assertEqual(rows["Root"]["device_count"], 4)    # tagged anywhere in the branch
        self.assertEqual(rows["Mid"]["group_count"], 1)      # Leaf
        self.assertEqual(rows["Mid"]["device_count"], 2)     # B + C
        self.assertEqual(rows["Leaf"]["group_count"], 0)
        self.assertEqual(rows["Leaf"]["device_count"], 1)
        self.assertEqual(tree_summary()["groups"], 4)

    def test_group_view_summary_renders(self):
        self.group("A")
        response = self.client.get(reverse("device_tree"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["tree_summary"]["groups"], 1)

    def test_creating_a_group_through_the_ui_nests_under_a_group(self):
        parent = self.group("Limit")
        self.client.post(reverse("device_group_add"), {"group_name": "Kalar", "parent": f"g:{parent.pk}"})
        self.assertEqual(Group.objects.get(name="Kalar").parent_id, parent.pk)
        # A device is refused even if one is posted directly.
        before = Group.objects.count()
        device = self.device("NCS")
        self.client.post(reverse("device_group_add"), {"group_name": "Bad", "parent": f"d:{device.pk}"})
        self.assertEqual(Group.objects.count(), before)


class IndependenceTests(Base):
    def payload(self, device, **changes):
        return {
            "edit-name": device.name, "edit-management_ip": str(device.management_ip),
            "edit-device_type": device.device_type, "edit-api_port": device.api_port,
            "edit-use_ssl": "true", "edit-username": device.username, "edit-password": "",
            "edit-incoming_monitoring_interface": "", "edit-description": "",
            "edit-group": f"g:{device.group_id}" if device.group_id else "",
            "edit-topology_parent": f"d:{device.topology_parent_id}" if device.topology_parent_id else "",
            **changes,
        }

    def test_changing_topology_parent_leaves_the_group_alone(self):
        group = self.group("Ahmad")
        ncs = self.device("NCS")
        limit = self.device("Limit-1", ncs)
        device = self.device("Tower-1", group=group)

        response = self.client.post(reverse("device_edit", args=[device.pk]),
                                    self.payload(device, **{"edit-topology_parent": f"d:{limit.pk}"}),
                                    HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200, response.content[:400])
        device.refresh_from_db()
        self.assertEqual(device.topology_parent_id, limit.pk)
        self.assertEqual(device.group_id, group.pk)      # untouched

    def test_changing_group_leaves_the_topology_parent_alone(self):
        group = self.group("Ali")
        ncs = self.device("NCS")
        limit = self.device("Limit-1", ncs)
        device = self.device("Kalar", parent=limit)

        response = self.client.post(reverse("device_edit", args=[device.pk]),
                                    self.payload(device, **{"edit-group": f"g:{group.pk}"}),
                                    HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200, response.content[:400])
        device.refresh_from_db()
        self.assertEqual(device.group_id, group.pk)
        self.assertEqual(device.topology_parent_id, limit.pk)   # untouched

    def test_the_two_views_show_different_structures(self):
        group = self.group("Limit")
        ncs = self.device("NCS", group=group)
        limit = self.device("Limit-1", ncs, group=group)
        self.device("Tower-1", limit)
        groups = self.rows(build_tree())
        chain = self.rows(build_topology())
        self.assertIn("Limit", groups)          # the group tree
        self.assertNotIn("NCS", groups)         # devices are not group-tree nodes
        self.assertIn("NCS", chain)             # the topology chain
        self.assertNotIn("Limit", chain)        # groups are not topology nodes

    def test_add_device_with_both_pickers(self):
        group = self.group("Ali")
        ncs = self.device("NCS")
        url = reverse("device_add")
        response = self.client.post(url, {
            "name": "Limit-2", "management_ip": "10.77.0.200", "device_type": "mikrotik",
            "api_port": "8729", "use_ssl": "true", "username": "api-user",
            "password": "secret-pass", "incoming_monitoring_interface": "", "description": "",
            "group": f"g:{group.pk}", "topology_parent": f"d:{ncs.pk}",
        })
        self.assertEqual(response.status_code, 302)
        created = Device.objects.get(name="Limit-2")
        self.assertEqual(created.group_id, group.pk)
        self.assertEqual(created.topology_parent_id, ncs.pk)
