"""DDoS Protection section on the device Settings page: NAT list + ONE SOS Public/Protection."""
import os
from decimal import Decimal
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from monitor.models import DeviceDDoSProtection, DeviceDDoSProtectionRule


class DDoSProtectionTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="protect-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="Protect router", management_ip="10.20.30.70", username="u",
                                            encrypted_password=encrypt_password("p"))
        self.page_url = reverse("device_sensors", args=[self.device.pk])
        self.save_url = reverse("device_ddos_protection", args=[self.device.pk])

    def save(self, names, values=None, sos="185.166.27.99", protection=False):
        data = {"rule_name": names, "sos_public": sos}
        if values is not None:
            data["rule_value"] = values
        if protection:
            data["protection_enabled"] = "1"
        return self.client.post(self.save_url, data)

    def protection(self):
        return DeviceDDoSProtection.objects.get(device=self.device)

    def test_section_renders_empty_on_first_load(self):
        page = self.client.get(self.page_url)
        self.assertContains(page, "DDoS Protection")
        self.assertContains(page, "SOS Public")
        self.assertContains(page, "Add Row")
        self.assertContains(page, 'id="natRulesBody"')
        self.assertContains(page, "Protection off")

    def test_one_sos_public_and_one_protection_for_the_whole_section(self):
        page = self.client.get(self.page_url).content.decode()
        saved_rows = page.split('id="natRulesBody"')[1].split("</tbody>")[0]
        self.assertIn('name="sos_public"', page)
        self.assertIn('name="protection_enabled"', page)
        # Nothing per-row: no SOS Public / Protection inputs inside the row list.
        self.assertNotIn('name="rule_sos_public"', page)
        self.assertNotIn('name="rule_protection"', page)
        self.assertNotIn('name="rule_name"', saved_rows)   # no saved rows yet
        form = page.split('id="deviceProtectionForm"')[1].split("</form>")[0]
        self.assertEqual(form.count('name="sos_public"'), 1)
        self.assertEqual(form.count('name="protection_enabled"'), 1)

    def test_save_persists_rows_and_the_single_sos_and_toggle(self):
        response = self.save(["1", "2", "4"], values=["25", "30", "40"], sos="185.166.27.16", protection=True)
        self.assertRedirects(response, self.page_url)
        protection = self.protection()
        self.assertEqual(protection.sos_public, "185.166.27.16")
        self.assertTrue(protection.enabled)
        self.assertEqual(list(protection.rules.values_list("name", "value")),
                         [("1", Decimal("25")), ("2", Decimal("30")), ("4", Decimal("40"))])

    def test_save_without_toggle_turns_protection_off(self):
        self.save(["1"], values=["25"], protection=True)
        self.assertTrue(self.protection().enabled)
        self.save(["1"], values=["25"], protection=False)
        self.assertFalse(self.protection().enabled)

    def test_saving_again_replaces_the_list_without_duplicating(self):
        self.save(["1", "2"], values=["10", "20"])
        self.save(["9"], values=["99"])
        self.assertEqual(list(self.protection().rules.values_list("name", flat=True)), ["9"])
        self.assertEqual(DeviceDDoSProtectionRule.objects.count(), 1)

    def test_blank_rows_are_dropped(self):
        self.save(["1", "", "  ", "7"], values=["25", "", "", ""])
        self.assertEqual(list(self.protection().rules.values_list("name", flat=True)), ["1", "7"])

    def test_rendered_values_round_trip(self):
        self.save(["uplink"], values=["25.5"], sos="185.166.27.16", protection=True)
        page = self.client.get(self.page_url).content.decode()
        self.assertIn('name="rule_name" value="uplink"', page)
        self.assertIn('name="sos_public" value="185.166.27.16"', page)
        self.assertIn("PROTECTION ON", page)

    def test_resave_keeps_switched_latch_for_unchanged_entries(self):
        self.save(["iQ-25-01"], values=["25"], protection=True)
        rule = self.protection().rules.get()
        rule.switched_at = timezone.now(); rule.switched_from = "185.166.27.16"; rule.save()
        self.save(["iQ-25-01"], values=["25"], protection=True)
        rule = self.protection().rules.get()
        self.assertIsNotNone(rule.switched_at)
        self.assertContains(self.client.get(self.page_url), "Switched to SOS Public (1 entry)")

    def test_turning_protection_off_clears_the_switch_latch(self):
        self.save(["iQ-25-01"], values=["25"], protection=True)
        rule = self.protection().rules.get()
        rule.switched_at = timezone.now(); rule.switched_from = "185.166.27.16"; rule.save()
        self.save(["iQ-25-01"], values=["25"], protection=False)
        self.assertIsNone(self.protection().rules.get().switched_at)
        self.assertContains(self.client.get(self.page_url), "Protection off")

    def test_changing_sos_public_rearms_every_entry(self):
        """Regression: a latch from an older SOS address blocked every later switch."""
        self.save(["iQ-25-01", "iQ-30-01"], values=["25", "30"], sos="199.199.199.199", protection=True)
        DeviceDDoSProtectionRule.objects.filter(protection=self.protection()).exclude(name="iQ-25-01").update(
            switched_at=timezone.now(), switched_from="185.166.27.19")
        self.save(["iQ-25-01", "iQ-30-01"], values=["25", "30"], sos="185.166.24.24", protection=True)
        rules = self.protection().rules
        self.assertEqual(rules.filter(switched_at__isnull=False).count(), 0)
        self.assertEqual({r.sos_public for r in rules.all()}, {"185.166.24.24"})

    def test_resaving_with_same_sos_keeps_the_latch(self):
        self.save(["iQ-25-01"], values=["25"], sos="185.166.24.24", protection=True)
        rule = self.protection().rules.get()
        rule.switched_at = timezone.now(); rule.switched_from = "185.166.24.24"; rule.save()
        self.assertContains(self.client.get(self.page_url), "Switched to SOS Public")
        self.save(["iQ-25-01"], values=["25"], sos="185.166.24.24", protection=True)

    def test_reader_cannot_save(self):
        self.client.force_login(get_user_model().objects.create_user(username="protect-reader"))
        self.assertEqual(self.save(["1"], values=["25"]).status_code, 403)
        self.assertFalse(DeviceDDoSProtection.objects.exists())
        self.assertContains(self.client.get(self.page_url), "Administrator access is required", status_code=200)

    def test_does_not_touch_ddos_thresholds_or_detection(self):
        from monitor.models import DeviceDDoSThreshold, DetectionState
        self.save(["1"], values=["25"])
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
        self.assertFalse(DetectionState.objects.exists())
