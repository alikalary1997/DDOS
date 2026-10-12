"""Reproduce the live pending-migration failure in Django's isolated test DB."""
import os
import secrets
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import connection, OperationalError
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.urls import reverse
from devices.models import Device, DeviceChange
from devices.services.management import remove_device
from public_ips.models import PublicIP


class DeletionSchemaRegressionTests(TransactionTestCase):
    def test_missing_audit_column_reproduces_failure_and_migration_restores_deletion(self):
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            admin = get_user_model().objects.create_user(username="schema-admin", is_staff=True)
            device = Device(name="Schema fixture", management_ip="172.26.241.88", username="test-api")
            device.set_password(secrets.token_urlsafe(24))
            device.save()
        device_id = device.pk
        ip = PublicIP.objects.create(address="8.8.8.8", device=device)
        ip_id = ip.pk
        self.client.force_login(admin)
        try:
            MigrationExecutor(connection).migrate([("devices", "0004_devicechange")])
            with patch("routeros_api.RouterOsApiPool") as api:
                with self.assertRaisesMessage(OperationalError, "has no column named router_cleanup_performed"):
                    remove_device(device, admin)
                self.assertTrue(Device.objects.filter(pk=device_id).exists())
                self.assertTrue(PublicIP.objects.filter(pk=ip_id).exists())
                self.assertEqual(DeviceChange.objects.count(), 0)
                api.assert_not_called()
        finally:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())
        with patch("routeros_api.RouterOsApiPool") as api:
            response = self.client.post(reverse("device_delete", args=[device_id]), {"confirm": "yes"}, HTTP_ACCEPT="application/json")
            self.assertEqual(response.status_code, 200)
            self.assertFalse(Device.objects.filter(pk=device_id).exists())
            self.assertFalse(PublicIP.objects.filter(pk=ip_id).exists())
            self.assertFalse(DeviceChange.objects.get(device_id_snapshot=device_id).router_cleanup_performed)
            api.assert_not_called()
