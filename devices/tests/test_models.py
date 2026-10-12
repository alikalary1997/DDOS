import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.core import serializers
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import IntegrityError, connection, transaction
from django.forms.models import model_to_dict, modelform_factory
from django.test import TestCase
from django.utils import timezone

from devices.models import Device


class DeviceTests(TestCase):
    def setUp(self):
        self.password = secrets.token_urlsafe(32)
        self.environment = patch.dict(os.environ, {
            "NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def device(self, **overrides):
        values = dict(name="Router", management_ip="192.0.2.10", username="api-user")
        values.update(overrides)
        device = Device(**values)
        device.set_password(self.password)
        return device

    def test_database_stores_only_fernet_ciphertext(self):
        device = self.device()
        device.save()
        with connection.cursor() as cursor:
            cursor.execute("SELECT encrypted_password FROM devices_device WHERE id = %s", [device.pk])
            stored = cursor.fetchone()[0]
        self.assertNotIn(self.password, stored)
        device.refresh_from_db()
        self.assertEqual(device.get_password(), self.password)
        self.assertTrue(device.use_ssl)
        self.assertEqual(device.api_port, 8729)
        self.assertTrue(device.enabled)
        self.assertIsNone(device.last_successful_connection)
        self.assertEqual(device.model, "")

    def test_plain_api_and_custom_ssl_port_are_supported(self):
        for ip, ssl, port in (("192.0.2.11", False, 8728), ("192.0.2.12", True, 4949)):
            device = self.device(management_ip=ip, use_ssl=ssl, api_port=port)
            device.save()
            device.refresh_from_db()
            self.assertEqual((device.use_ssl, device.api_port), (ssl, port))

    def test_required_fields_and_device_type_are_validated_on_save(self):
        for field, value in (("name", ""), ("name", "   "), ("username", ""),
                             ("username", "   "), ("device_type", "invalid")):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    self.device(**{field: value}).save()
        self.assertEqual(Device.objects.count(), 0)

    def test_management_ip_rejects_hostnames_invalid_and_scoped_addresses(self):
        for value in ("", "router.example", "999.1.1.1", "127.0.0.1:8728", "fe80::1%eth0"):
            with self.subTest(ip=value):
                with self.assertRaises(ValidationError):
                    self.device(management_ip=value).save()
        self.assertEqual(Device.objects.count(), 0)

    def test_ipv6_is_canonicalized_and_duplicates_are_rejected(self):
        device = self.device(management_ip="2001:0db8:0000:0000:0000:0000:0000:0001")
        device.save()
        self.assertEqual(device.management_ip, "2001:db8::1")
        with self.assertRaises(ValidationError):
            self.device(management_ip="2001:db8::1").save()

    def test_ipv4_mapped_ipv6_cannot_bypass_endpoint_uniqueness(self):
        self.device().save()
        with self.assertRaises(ValidationError):
            self.device(management_ip="::ffff:192.0.2.10").save()

    def test_invalid_ports_are_rejected_on_save(self):
        for port in (0, -1, 65536, "invalid", None):
            with self.subTest(port=port):
                with self.assertRaises(ValidationError):
                    self.device(api_port=port).save()

    def test_boundary_ports_are_allowed(self):
        self.device(api_port=1).save()
        self.device(api_port=65535).save()
        self.assertEqual(Device.objects.count(), 2)

    def test_duplicate_endpoint_rejected_but_different_port_allowed(self):
        self.device().save()
        with self.assertRaises(ValidationError):
            self.device(name="Another router").save()
        self.device(api_port=8728, use_ssl=False).save()
        self.assertEqual(Device.objects.count(), 2)

    def test_database_uniqueness_survives_bulk_save_bypass(self):
        self.device().save()
        with self.assertRaises(IntegrityError), transaction.atomic():
            Device.objects.bulk_create([self.device(name="Duplicate")])

    def test_database_port_constraint_survives_bulk_save_bypass(self):
        for port in (0, 65536):
            with self.subTest(port=port):
                with self.assertRaises(IntegrityError), transaction.atomic():
                    Device.objects.bulk_create([self.device(api_port=port)])

    def test_plaintext_cannot_be_saved_to_credential_field(self):
        device = self.device()
        device.encrypted_password = self.password
        with self.assertRaises(ValidationError) as caught:
            device.save()
        self.assertNotIn(self.password, str(caught.exception))
        self.assertEqual(Device.objects.count(), 0)

    def test_bulk_writes_cannot_store_plaintext(self):
        device = self.device()
        device.encrypted_password = self.password
        with self.assertRaises(ValidationError), transaction.atomic():
            Device.objects.bulk_create([device])
        device = self.device()
        device.save()
        with self.assertRaises(ValidationError), transaction.atomic():
            Device.objects.filter(pk=device.pk).update(encrypted_password=self.password)
        device.refresh_from_db()
        self.assertEqual(device.get_password(), self.password)

    def test_serializers_forms_and_model_dict_exclude_password(self):
        device = self.device()
        device.save()
        serialized = serializers.serialize("json", [device])
        self.assertNotIn("encrypted_password", serialized)
        self.assertNotIn(device.encrypted_password, serialized)
        self.assertNotIn(self.password, serialized)
        self.assertNotIn("encrypted_password", model_to_dict(device))
        form = modelform_factory(Device, fields="__all__")
        self.assertNotIn("encrypted_password", form.base_fields)
        self.assertNotIn(self.password, str(device))
        self.assertNotIn(self.password, repr(device))

    def test_missing_key_prevents_credential_writes(self):
        device = self.device()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ImproperlyConfigured):
                device.save()
        self.assertEqual(Device.objects.count(), 0)

    def test_updates_preserve_password_and_created_date(self):
        device = self.device()
        device.save()
        created, updated, token = device.created_at, device.updated_at, device.encrypted_password
        device.description = "Branch router"
        device.enabled = False
        device.model = "Retrieved model"
        device.last_successful_connection = timezone.now()
        device.save()
        device.refresh_from_db()
        self.assertEqual(device.created_at, created)
        self.assertGreater(device.updated_at, updated)
        self.assertEqual(device.encrypted_password, token)
        self.assertEqual(device.get_password(), self.password)
        self.assertFalse(device.enabled)
        self.assertIsNotNone(device.last_successful_connection)

    def test_password_can_be_replaced_explicitly(self):
        device = self.device()
        device.save()
        replacement = secrets.token_urlsafe(32)
        device.set_password(replacement)
        device.save()
        device.refresh_from_db()
        self.assertEqual(device.get_password(), replacement)
