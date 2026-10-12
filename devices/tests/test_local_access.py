import os
import secrets
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.db import connection
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from netshield import settings as base_settings
from netshield import settings_local as local_settings


class LocalSettingsIsolationTests(SimpleTestCase):
    def test_normal_settings_have_no_local_mode_or_local_guard(self):
        self.assertFalse(getattr(base_settings, "LOCAL_DEVELOPMENT_ACCESS", False))
        self.assertNotIn("netshield.local_development.LocalDevelopmentOnlyMiddleware", base_settings.MIDDLEWARE)
        self.assertFalse(hasattr(base_settings, "SESSION_COOKIE_AGE"))
        self.assertFalse(hasattr(base_settings, "SESSION_COOKIE_NAME"))

    def test_local_settings_use_real_auth_and_persistent_database_sessions(self):
        self.assertEqual(local_settings.SESSION_ENGINE, "django.contrib.sessions.backends.db")
        self.assertEqual(local_settings.SESSION_COOKIE_AGE, 30 * 24 * 60 * 60)
        self.assertFalse(local_settings.SESSION_EXPIRE_AT_BROWSER_CLOSE)
        self.assertFalse(local_settings.SESSION_SAVE_EVERY_REQUEST)
        self.assertTrue(local_settings.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(local_settings.SESSION_COOKIE_SAMESITE, "Lax")
        self.assertIsNone(local_settings.SESSION_COOKIE_DOMAIN)
        self.assertIn("django.contrib.auth.middleware.AuthenticationMiddleware", local_settings.MIDDLEWARE)
        self.assertIn("django.middleware.csrf.CsrfViewMiddleware", local_settings.MIDDLEWARE)
        self.assertEqual(base_settings.MIDDLEWARE, local_settings.MIDDLEWARE[1:])


@override_settings(
    DEBUG=True,
    LOCAL_DEVELOPMENT_ACCESS=True,
    ALLOWED_HOSTS=local_settings.ALLOWED_HOSTS,
    MIDDLEWARE=local_settings.MIDDLEWARE,
    SESSION_ENGINE=local_settings.SESSION_ENGINE,
    SESSION_COOKIE_NAME=local_settings.SESSION_COOKIE_NAME,
    SESSION_COOKIE_AGE=local_settings.SESSION_COOKIE_AGE,
    SESSION_EXPIRE_AT_BROWSER_CLOSE=False,
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_SAVE_EVERY_REQUEST=False,
)
class LocalAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin_password = secrets.token_urlsafe(32)
        cls.reader_password = secrets.token_urlsafe(32)
        users = get_user_model()
        cls.admin = users.objects.create_user(username="local-admin", password=cls.admin_password, is_staff=True)
        cls.reader = users.objects.create_user(username="local-reader", password=cls.reader_password)

    def setUp(self):
        self.client = self.new_client()
        environment = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        environment.start()
        self.addCleanup(environment.stop)
        self.payload = {
            "name": "Local router", "management_ip": "192.0.2.99", "device_type": "mikrotik",
            "api_port": "8729", "use_ssl": "true", "username": "api-user",
            "password": secrets.token_urlsafe(32), "description": "",
        }

    def new_client(self):
        return Client(enforce_csrf_checks=True, HTTP_HOST="127.0.0.1:8000", REMOTE_ADDR="127.0.0.1")

    def sign_in(self, user=None, password=None):
        user = self.admin if user is None else user
        password = self.admin_password if password is None else password
        self.client.get(reverse("device_login"))
        response = self.client.post(reverse("device_login"), {
            "username": user.username, "password": password,
            "csrfmiddlewaretoken": self.client.cookies["csrftoken"].value,
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(password not in response.content.decode())
        return response

    def test_anonymous_local_user_is_not_logged_in_or_made_admin(self):
        before = get_user_model().objects.count()
        response = self.client.get(reverse("devices"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/devices/login/?next=/devices/")
        self.assertEqual(get_user_model().objects.count(), before)
        self.assertNotIn(local_settings.SESSION_COOKIE_NAME, response.cookies)

    def test_login_issues_host_only_httponly_30_day_cookie(self):
        response = self.sign_in()
        cookie = response.cookies[local_settings.SESSION_COOKIE_NAME]
        self.assertEqual(int(cookie["max-age"]), 30 * 24 * 60 * 60)
        self.assertTrue(cookie["expires"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["domain"], "")
        self.assertTrue(Session.objects.filter(session_key=cookie.value).exists())
        self.assertNotIn("sessionid", response.cookies)

    def test_saved_session_works_with_a_fresh_client_without_another_login(self):
        self.sign_in()
        resumed = self.new_client()
        resumed.cookies[local_settings.SESSION_COOKIE_NAME] = self.client.cookies[local_settings.SESSION_COOKIE_NAME].value
        response = resumed.get(reverse("devices"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.wsgi_request.user.pk, self.admin.pk)
        self.assertContains(response, 'id="addDeviceForm"')

    def test_expired_session_requires_login_instead_of_automatic_authentication(self):
        self.sign_in()
        session_key = self.client.cookies[local_settings.SESSION_COOKIE_NAME].value
        Session.objects.filter(session_key=session_key).update(expire_date=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.get(reverse("devices")).status_code, 302)

    def test_bad_password_cannot_create_authenticated_session(self):
        self.client.get(reverse("device_login"))
        bad_password = secrets.token_urlsafe(32)
        response = self.client.post(reverse("device_login"), {
            "username": self.admin.username, "password": bad_password,
            "csrfmiddlewaretoken": self.client.cookies["csrftoken"].value,
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(bad_password not in response.content.decode())
        self.assertEqual(self.client.get(reverse("devices")).status_code, 302)

    def test_admin_can_add_with_real_login_and_csrf(self):
        self.sign_in()
        response = self.client.post(reverse("device_add"), {
            **self.payload, "csrfmiddlewaretoken": self.client.cookies["csrftoken"].value,
        })
        self.assertEqual(response.status_code, 302)
        from devices.models import Device
        device = Device.objects.get()
        self.assertTrue(device.get_password() == self.payload["password"])
        self.assertTrue(device.encrypted_password != self.payload["password"])

    def test_local_reader_remains_unauthorized_to_add(self):
        self.sign_in(self.reader, self.reader_password)
        page = self.client.get(reverse("devices"))
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, 'id="addDeviceForm"')
        response = self.client.post(reverse("device_add"), {
            **self.payload, "csrfmiddlewaretoken": self.client.cookies["csrftoken"].value,
        })
        self.assertEqual(response.status_code, 403)

    def test_missing_csrf_still_rejects_an_authenticated_administrator(self):
        self.sign_in()
        self.assertEqual(self.client.post(reverse("device_add"), self.payload).status_code, 403)

    def test_cross_origin_post_is_rejected_even_with_valid_csrf_token(self):
        self.sign_in()
        response = self.client.post(reverse("device_add"), {
            **self.payload, "csrfmiddlewaretoken": self.client.cookies["csrftoken"].value,
        }, HTTP_ORIGIN="https://untrusted.example")
        self.assertEqual(response.status_code, 403)

    def test_nonloopback_peer_is_rejected_even_with_loopback_host_and_valid_login(self):
        self.sign_in()
        for address in ("192.0.2.1", "10.1.2.3", "2001:db8::1", "", "invalid"):
            with self.subTest(address=address):
                self.assertEqual(self.client.get(reverse("devices"), REMOTE_ADDR=address).status_code, 403)

    def test_nonlocal_host_cannot_use_local_profile_even_with_a_permissive_allowlist(self):
        with override_settings(ALLOWED_HOSTS=["*"]):
            self.assertEqual(self.client.get(reverse("device_login"), HTTP_HOST="netshield.example").status_code, 403)

    def test_forwarding_headers_cannot_bypass_local_guard(self):
        for header in ("HTTP_FORWARDED", "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED_HOST", "HTTP_X_FORWARDED_PROTO", "HTTP_X_REAL_IP"):
            with self.subTest(header=header):
                self.assertEqual(self.client.get(reverse("device_login"), **{header: "127.0.0.1"}).status_code, 403)

    def test_local_guard_fails_closed_when_debug_is_disabled(self):
        with override_settings(DEBUG=False):
            self.assertEqual(self.client.get(reverse("device_login")).status_code, 403)

    def test_local_guard_fails_closed_without_explicit_local_setting(self):
        with override_settings(LOCAL_DEVELOPMENT_ACCESS=False):
            self.assertEqual(self.client.get(reverse("device_login")).status_code, 403)

    def test_ipv6_loopback_is_supported_but_still_requires_login(self):
        response = self.client.get(reverse("devices"), HTTP_HOST="[::1]:8000", REMOTE_ADDR="::1")
        self.assertEqual(response.status_code, 302)

    def test_existing_admin_logout_invalidates_persistent_login(self):
        self.sign_in()
        self.client.post(reverse("admin:logout"), {"csrfmiddlewaretoken": self.client.cookies["csrftoken"].value})
        self.assertEqual(self.client.get(reverse("devices")).status_code, 302)

    def test_account_deactivation_invalidates_access(self):
        self.sign_in()
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)
        self.assertEqual(self.client.get(reverse("devices")).status_code, 302)

    def test_revoking_admin_privileges_removes_add_access_without_logging_in_again(self):
        self.sign_in()
        get_user_model().objects.filter(pk=self.admin.pk).update(is_staff=False, is_superuser=False)
        response = self.client.get(reverse("devices"))
        self.assertNotContains(response, 'id="addDeviceForm"')
        self.assertEqual(self.client.post(reverse("device_add"), {
            **self.payload, "csrfmiddlewaretoken": self.client.cookies["csrftoken"].value,
        }).status_code, 403)

    def test_password_change_invalidates_old_session(self):
        self.sign_in()
        self.admin.set_password(secrets.token_urlsafe(32))
        self.admin.save()
        self.assertEqual(self.client.get(reverse("devices")).status_code, 302)

    def test_monitoring_reads_do_not_rewrite_or_extend_local_sessions(self):
        self.sign_in()
        key = self.client.cookies[local_settings.SESSION_COOKIE_NAME].value
        before = Session.objects.get(session_key=key).expire_date
        with patch("monitor.services.mikrotik_api.get_firewall_rules", return_value=[]), CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("monitoring_data"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Session.objects.get(session_key=key).expire_date, before)
        self.assertTrue(all(not (query["sql"].startswith("UPDATE") and "django_session" in query["sql"]) for query in queries))

    def test_existing_pages_render_in_local_mode(self):
        self.sign_in()
        for url in ("/", "/devices/", "/public-ips/", "/traffic-monitor/", "/ddos-detection/", "/alerts/", "/reports/", "/settings/"):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)
