"""Deleting a Group: devices are kept and untagged, nested groups go with it."""
import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from devices.models import Device, Group
from devices.services.credentials import encrypt_password
from devices.services.tree_view import build_tree, delete_impact, delete_group


class GroupDeleteTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="group-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.counter = 0

    def device(self, name, group=None):
        self.counter += 1
        return Device.objects.create(
            name=name, management_ip=f"10.77.0.{self.counter}", username="api-user",
            encrypted_password=encrypt_password(secrets.token_urlsafe(10)), group=group)

    def group(self, name, parent=None):
        group = Group(name=name)
        group.set_parent(parent)
        group.full_clean()
        group.save()
        return group

    def test_device_is_kept_and_untagged_when_its_group_is_deleted(self):
        tag = self.group("Ahmad")
        device = self.device("Tower-A", group=tag)
        delete_group(tag)
        device.refresh_from_db()
        self.assertIsNotNone(Device.objects.filter(pk=device.pk).first(), "the device is never deleted")
        self.assertIsNone(device.group_id, "it simply becomes untagged")
        self.assertFalse(Group.objects.filter(pk=tag.pk).exists())

    def test_impact_reports_devices_and_subgroups_before_deleting(self):
        core = self.group("Core")
        limit = self.group("Limit-1", core)
        server = self.group("Kalar", limit)
        self.device("Conneciton-Kalar", group=server)
        self.device("Connection-Ranya", group=limit)
        impact = delete_impact(core)
        self.assertEqual(impact["devices"], 2, "counts devices at every depth")
        self.assertEqual(impact["subgroups"], 2)
        # Nothing is removed by merely asking.
        self.assertEqual(Group.objects.count(), 3)

    def test_nested_subgroups_are_removed_with_the_parent(self):
        core = self.group("Core")
        limit = self.group("Limit-1", core)
        self.device("Leaf", group=limit)
        result = delete_group(core)
        self.assertEqual(result["groups"], 2)
        self.assertEqual(Group.objects.count(), 0)
        self.assertEqual(Device.objects.get(name="Leaf").group_id, None)

    def test_other_groups_and_their_devices_are_untouched(self):
        keep = self.group("Keep")
        drop = self.group("Drop")
        kept = self.device("Stays", group=keep)
        self.device("Moves", group=drop)
        delete_group(drop)
        kept.refresh_from_db()
        self.assertEqual(kept.group_id, keep.pk, "an unrelated device keeps its tag")
        self.assertTrue(Group.objects.filter(pk=keep.pk).exists())

    def test_empty_group_delete_is_clean(self):
        empty = self.group("Kalar")
        result = delete_group(empty)
        self.assertEqual((result["devices"], result["groups"]), (0, 1))
        self.assertEqual(Group.objects.count(), 0)

    def test_delete_view_removes_the_group_and_reports_untagging(self):
        tag = self.group("Ahmad")
        device = self.device("Tower-A", group=tag)
        response = self.client.post(reverse("device_group_delete", args=[tag.pk]),
                                    {"next": "tree"}, follow=True)
        self.assertEqual(response.status_code, 200)
        device.refresh_from_db()
        self.assertIsNone(device.group_id)
        messages = [str(message) for message in response.context["messages"]]
        self.assertTrue(any("deleted" in text for text in messages))
        self.assertTrue(any("untagged" in text for text in messages))

    def test_delete_returns_to_the_tree_page(self):
        tag = self.group("Ahmad")
        response = self.client.post(reverse("device_group_delete", args=[tag.pk]), {"next": "tree"})
        self.assertRedirects(response, reverse("device_tree"))

    def test_delete_requires_staff(self):
        tag = self.group("Ahmad")
        member = get_user_model().objects.create_user(username="member", password="x")
        self.client.force_login(member)
        response = self.client.post(reverse("device_group_delete", args=[tag.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Group.objects.filter(pk=tag.pk).exists())

    def test_delete_rejects_get(self):
        tag = self.group("Ahmad")
        self.assertEqual(self.client.get(reverse("device_group_delete", args=[tag.pk])).status_code, 405)

    def test_missing_group_reports_instead_of_crashing(self):
        response = self.client.post(reverse("device_group_delete", args=[9999]), {"next": "tree"}, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_tree_page_offers_delete_with_a_clear_warning(self):
        core = self.group("Core")
        limit = self.group("Limit-1", core)
        self.device("Leaf", group=limit)
        html = self.client.get(reverse("device_tree")).content.decode()
        self.assertIn("data-group-delete", html)
        self.assertIn("will be untagged and kept in inventory", html)
        self.assertIn("cannot be undone", html)
        # The row's own warning names the real numbers.
        row = build_tree()[0]
        self.assertIn("1 device will be untagged", row["delete_warning"])
        self.assertIn("1 nested sub-group will be removed", row["delete_warning"])
