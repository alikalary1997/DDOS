import os
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device


class DeviceNOCUITests(TestCase):
    def setUp(self):
        self.actor = get_user_model().objects.create_user(username="noc-admin", is_staff=True)
        self.client.force_login(self.actor)
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            self.device = Device(name="Actual router", management_ip="10.3.15.122",
                                 username="private-api-user", incoming_monitoring_interface="ether7")
            self.device.set_password("private-api-password")
            self.device.save()

    def test_grid_matrix_inspector_and_actions_use_real_rows_without_router_calls(self):
        with patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.get(reverse("devices"))
        pool.assert_not_called()
        self.assertContains(response, f'data-inspect-device="{self.device.pk}"', count=1)
        self.assertContains(response, f'aria-label="Actions for {self.device.name}"')
        self.assertContains(response, '<strong class="noc-name" data-cell="name">Actual router</strong>', html=True)
        for text in ('data-view="matrix"', 'data-inventory-view="matrix"', 'data-inspector-tab="audit"',
                     'IP Address', 'Interface Traffic', 'Uptime', 'Configured sensors',
                     'Actual router', '10.3.15.122', 'Not Tested', 'Not available',
                     reverse("device_raw_provisioning", args=[self.device.pk]),
                     reverse("device_edit", args=[self.device.pk]),
                     reverse("device_delete", args=[self.device.pk])):
            self.assertContains(response, text)
        for text in ("private-api-user", "private-api-password", self.device.encrypted_password, "Live Online"):
            self.assertNotContains(response, text)

    def test_real_zero_metrics_and_failed_snapshots(self):
        Device.objects.filter(pk=self.device.pk).update(last_connection_test=timezone.now(),
            last_connection_test_succeeded=True, cpu_usage=0, total_memory=1024, free_memory=1024)
        response = self.client.get(reverse("devices"))
        row = response.context["device_rows"][0]
        self.assertEqual(row["cpu_display"], "0%")
        self.assertEqual(row["ram_usage_percent"], 0)
        self.assertContains(response, "Last Test Successful")
        Device.objects.filter(pk=self.device.pk).update(last_connection_test_succeeded=False)
        row = self.client.get(reverse("devices")).context["device_rows"][0]
        self.assertEqual(row["cpu_display"], "Not available")
        self.assertIsNone(row["ram_usage_percent"])

    def test_reader_cannot_see_management_actions_and_revalidation_is_visible(self):
        Device.objects.filter(pk=self.device.pk).update(raw_preflight_message="Device configuration changed. Validate again.")
        reader = get_user_model().objects.create_user(username="noc-reader")
        self.client.force_login(reader)
        response = self.client.get(reverse("devices"))
        self.assertContains(response, "Needs Revalidation")
        self.assertNotContains(response, 'data-test-connection')
        self.assertNotContains(response, reverse("device_delete", args=[self.device.pk]))
