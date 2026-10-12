from decimal import Decimal
from html.parser import HTMLParser
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import Client, TestCase
from django.urls import reverse

from monitor.models import DETECTION_METRICS, DDoSDetectionSettings, RAWMonitoringSettings


class DDoSSettingsTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="threshold-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="threshold-reader")
        self.client.force_login(self.admin)
        self.url = reverse("settings")
        self.values = {"total_pps_warning": "10000", "total_pps_attack": "50000",
                       "bandwidth_mbps_warning": "100", "bandwidth_mbps_attack": "500",
                       "syn_pps_warning": "2000", "syn_pps_attack": "10000",
                       "udp_pps_warning": "5000", "udp_pps_attack": "20000"}

    def post(self, values=None):
        return self.client.post(self.url, {"settings_section": "ddos", **(values if values is not None else self.values)})

    def saved(self):
        return DDoSDetectionSettings.objects.values().get(pk=1)

    def test_initial_examples_and_native_form_not_nested_in_preview(self):
        saved = self.saved()
        for name, value in self.values.items():
            self.assertEqual(saved[name], Decimal(value))
        response = self.client.get(self.url)
        self.assertContains(response, "not validated production thresholds")
        self.assertContains(response, "Save Changes")
        self.assertEqual(len(response.context["ddos_settings_form"].fields), 8)
        class Forms(HTMLParser):
            current = None
            nested = False
            fields = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "form":
                    self.nested = self.nested or self.current is not None
                    self.current = attrs.get("id")
                if tag == "input" and self.current == "ddosSettingsForm" and attrs.get("type") == "number":
                    self.fields.append(attrs.get("name"))
            def handle_endtag(self, tag):
                if tag == "form":
                    self.current = None
        parser = Forms()
        parser.feed(response.content.decode())
        self.assertFalse(parser.nested)
        self.assertEqual(set(parser.fields), set(self.values))

    def test_all_eight_values_persist_and_syn_1500_survives_refresh(self):
        values = {"total_pps_warning": "9000", "total_pps_attack": "45000",
                  "bandwidth_mbps_warning": "95.125", "bandwidth_mbps_attack": "450.5",
                  "syn_pps_warning": "1500", "syn_pps_attack": "9000",
                  "udp_pps_warning": "4000", "udp_pps_attack": "19000"}
        interval = RAWMonitoringSettings.objects.get(pk=1).polling_interval
        with patch("routeros_api.RouterOsApiPool") as pool, patch("subprocess.Popen") as launch:
            self.assertRedirects(self.post(values), self.url + "#detectionSettings")
            for _ in range(2):
                response = self.client.get(self.url)
                for name, value in values.items():
                    self.assertEqual(Decimal(response.context["ddos_settings_form"][name].value()), Decimal(value))
            pool.assert_not_called()
            launch.assert_not_called()
        self.assertEqual(self.saved()["syn_pps_warning"], Decimal(1500))
        self.assertEqual(RAWMonitoringSettings.objects.get(pk=1).polling_interval, interval)

    def test_missing_empty_invalid_nonfinite_and_negative_values_reject_whole_save(self):
        before = self.saved()
        for name in self.values:
            for value in ("", "abc", "NaN", "Infinity", "-1", "0.0001"):
                with self.subTest(field=name, value=value):
                    response = self.post({**self.values, name: value})
                    self.assertEqual(response.status_code, 400)
                    self.assertTrue(response.context["ddos_settings_form"].errors)
                    self.assertEqual(self.saved(), before)
            missing = dict(self.values)
            del missing[name]
            self.assertEqual(self.post(missing).status_code, 400)
        self.assertEqual(self.saved(), before)

    def test_attack_must_exceed_warning_for_each_metric_and_zero_warning_is_valid(self):
        for metric, _ in DETECTION_METRICS:
            for attack in ("10", "9"):
                response = self.post({**self.values, metric + "_warning": "10", metric + "_attack": attack})
                self.assertEqual(response.status_code, 400)
                self.assertContains(response, "Attack must be greater than Warning", status_code=400)
            self.assertEqual(self.post({**self.values, metric + "_warning": "0", metric + "_attack": "0.001"}).status_code, 302)

    def test_administrator_authentication_and_csrf_required(self):
        self.assertEqual(Client().post(self.url, {"settings_section": "ddos", **self.values}).status_code, 302)
        self.client.force_login(self.reader)
        self.assertEqual(self.post().status_code, 403)
        form = self.client.get(self.url).context["ddos_settings_form"]
        self.assertTrue(all(field.disabled for field in form.fields.values()))
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        payload = {"settings_section": "ddos", **self.values}
        self.assertEqual(client.post(self.url, payload).status_code, 403)
        client.get(self.url)
        self.assertEqual(client.post(self.url, payload, HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value).status_code, 302)

    def test_seed_reexecution_and_other_settings_do_not_overwrite_saved_values(self):
        self.post({**self.values, "syn_pps_warning": "1500"})
        seed = import_module("monitor.migrations.0002_ddosdetectionsettings").seed_examples
        seed(apps, SimpleNamespace(connection=connection))
        before = self.saved()
        self.client.post(self.url, {"polling_interval": 15})
        self.client.get(self.url)
        self.assertEqual(self.saved(), before)
        self.assertEqual(DDoSDetectionSettings.objects.count(), 1)

    def test_database_constraints_protect_warning_attack_and_singleton(self):
        for metric, _ in DETECTION_METRICS:
            for values in ({metric + "_warning": -1}, {metric + "_attack": 0}):
                with self.assertRaises(IntegrityError), transaction.atomic():
                    DDoSDetectionSettings.objects.filter(pk=1).update(**values)
        with self.assertRaises(IntegrityError), transaction.atomic():
            DDoSDetectionSettings.objects.create(pk=2)

    def test_database_failure_reports_error_and_keeps_submitted_form(self):
        before = self.saved()
        with patch("monitor.forms.DDoSDetectionSettingsForm.save", side_effect=DatabaseError):
            response = self.post({**self.values, "syn_pps_warning": "1500"})
        self.assertContains(response, "Thresholds could not be saved", status_code=400)
        self.assertEqual(response.context["ddos_settings_form"]["syn_pps_warning"].value(), "1500")
        self.assertEqual(self.saved(), before)
