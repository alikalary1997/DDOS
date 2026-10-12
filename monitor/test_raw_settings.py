from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import Client, TestCase
from django.urls import reverse

from monitor.models import POLLING_INTERVALS, RAWMonitoringSettings
from monitor.services.raw_settings import polling_interval, sample_freshness_seconds


class RAWSettingsTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="interval-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="interval-reader")
        self.client.force_login(self.admin)

    def test_default_is_persisted_and_admin_can_save_all_supported_values(self):
        self.assertEqual(RAWMonitoringSettings.objects.get(pk=1).polling_interval, 5)
        with patch("routeros_api.RouterOsApiPool") as pool:
            for seconds in POLLING_INTERVALS:
                response = self.client.post(reverse("settings"), {"polling_interval": seconds})
                self.assertEqual(response.status_code, 302)
                self.assertEqual(polling_interval(), seconds)
                self.assertContains(self.client.get(reverse("settings")), f'value="{seconds}" selected')
                self.assertContains(self.client.get(reverse("public_ips")), f'data-polling-interval>{seconds}</span>')
        pool.assert_not_called()
        self.assertEqual(RAWMonitoringSettings.objects.count(), 1)

    def test_invalid_values_rejected_by_form_and_database(self):
        for value in ("", "0", "3", "-5", "61", "5.0", "five"):
            self.assertEqual(self.client.post(reverse("settings"), {"polling_interval": value}).status_code, 400)
        self.assertEqual(polling_interval(), 5)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RAWMonitoringSettings.objects.filter(pk=1).update(polling_interval=3)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RAWMonitoringSettings.objects.create(pk=2, polling_interval=5)

    def test_changes_require_active_admin_authentication_post_and_csrf(self):
        anonymous = Client()
        self.assertEqual(anonymous.post(reverse("settings"), {"polling_interval": 60}).status_code, 302)
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(reverse("settings"), {"polling_interval": 60}).status_code, 403)
        self.assertContains(self.client.get(reverse("settings")), 'disabled')
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.admin)
        self.assertEqual(csrf.post(reverse("settings"), {"polling_interval": 60}).status_code, 403)
        csrf.get(reverse("settings"))
        response = csrf.post(reverse("settings"), {"polling_interval": 60},
                             HTTP_X_CSRFTOKEN=csrf.cookies["csrftoken"].value)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(polling_interval(), 60)

    def test_configuration_is_uncached_and_freshness_handles_interval_transition(self):
        self.assertEqual(polling_interval(), 5)
        RAWMonitoringSettings.objects.filter(pk=1).update(polling_interval=60)
        self.assertEqual(polling_interval(), 60)
        self.assertEqual(sample_freshness_seconds(), 63)
        RAWMonitoringSettings.objects.filter(pk=1).update(polling_interval=2)
        self.assertEqual(sample_freshness_seconds(60), 63)
        self.assertEqual(sample_freshness_seconds(2), 5)

