import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from devices.services.targets import TargetPolicyError, validate_target
from netshield.device_policy import load_device_policy


class TargetPolicyTests(SimpleTestCase):
    def device(self, address):
        return SimpleNamespace(pk=42, management_ip=address, api_port=8728)

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=("10.3.15.0/24",))
    def test_allowed_subnet_and_wrong_subnet(self):
        self.assertEqual(validate_target(self.device("10.3.15.122")), "10.3.15.122")
        with self.assertRaises(TargetPolicyError) as caught:
            validate_target(self.device("10.3.16.122"))
        self.assertEqual(caught.exception.code, "outside_allowlist")

    def test_empty_and_missing_policy_deny_all(self):
        for networks in ((), None):
            with override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=networks):
                with self.assertRaises(TargetPolicyError):
                    validate_target(self.device("10.3.15.122"))
        with override_settings():
            from django.conf import settings
            del settings.DEVICE_CONNECTION_ALLOWED_NETWORKS
            with self.assertRaises(TargetPolicyError) as caught:
                validate_target(self.device("10.3.15.122"))
            self.assertEqual(caught.exception.code, "empty_allowlist")

    def test_invalid_cidr_or_wrong_configuration_type_never_falls_back(self):
        for values in (("bad-cidr",), ("10.3.15.122/24",), (123,), "10.3.15.0/24"):
            with override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=values):
                with self.assertRaises(TargetPolicyError) as caught:
                    validate_target(self.device("10.3.15.122"))
                self.assertEqual(caught.exception.code, "invalid_allowlist")

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=("10.3.15.0/24",))
    def test_invalid_saved_ip_hostname_and_scoped_ipv6(self):
        for address in ("not-an-ip", "router.example", "10.3.15.999", "fe80::1%ether5"):
            with self.assertRaises(TargetPolicyError) as caught:
                validate_target(self.device(address))
            self.assertEqual(caught.exception.code, "invalid_target")

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=("0.0.0.0/0", "::/0"))
    def test_special_addresses_remain_forbidden_even_with_matching_policy(self):
        for address in ("127.0.0.1", "169.254.1.2", "224.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "fe80::1"):
            with self.assertRaises(TargetPolicyError):
                validate_target(self.device(address))

    def test_explicit_host_ipv6_and_whitespace_cidr(self):
        for address, entry in (("10.3.15.122", "10.3.15.122"),
                               ("10.3.15.122", " 10.3.15.0/24 "),
                               ("2001:db8::5", "2001:db8::/64")):
            with override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=(entry,)):
                self.assertEqual(validate_target(self.device(address)), address)

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=("10.3.15.0/24",),
                       DEVICE_CONNECTION_ALLOWLIST_SOURCE="environment:NETSHIELD_DEVICE_ALLOWED_NETWORKS")
    def test_administrator_logs_identify_policy_and_device_but_error_does_not_expose_policy(self):
        device = self.device("10.3.16.122")
        device.username = "SECRET-USER"
        device.encrypted_password = "SECRET-TOKEN"
        with self.assertLogs("netshield.target_policy", level="WARNING") as logs:
            with self.assertRaises(TargetPolicyError) as caught:
                validate_target(device)
        text = "\n".join(logs.output)
        for value in ("device_id=42", "management_ip=10.3.16.122", "10.3.15.0/24", "NETSHIELD_DEVICE_ALLOWED_NETWORKS", "reason=outside_allowlist"):
            self.assertIn(value, text)
        self.assertNotIn(device.username, text)
        self.assertNotIn(device.encrypted_password, text)
        self.assertNotIn("10.3.15.0/24", str(caught.exception))


class DeploymentPolicyTests(SimpleTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "device_management_allowlist.json"
        self.config.write_text(json.dumps({"allowed_networks": ["10.1.0.1/32"],
            "local_additional_networks": ["10.2.0.0/24"]}), encoding="utf-8")
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_explicit_file_profiles_preserve_their_separate_policies(self):
        self.assertEqual(load_device_policy(self.root)[0], ("10.1.0.1/32",))
        self.assertEqual(load_device_policy(self.root, local=True)[0], ("10.1.0.1/32", "10.2.0.0/24"))

    def test_environment_is_authoritative_in_both_profiles_including_empty_override(self):
        for local in (False, True):
            with patch.dict(os.environ, {"NETSHIELD_DEVICE_ALLOWED_NETWORKS": " 10.4.0.0/24, 10.5.0.1/32 "}):
                self.assertEqual(load_device_policy(self.root, local=local)[0], ("10.4.0.0/24", "10.5.0.1/32"))
            with patch.dict(os.environ, {"NETSHIELD_DEVICE_ALLOWED_NETWORKS": ""}):
                self.assertEqual(load_device_policy(self.root, local=local)[0], ())

    def test_missing_file_denies_all(self):
        self.config.unlink()
        self.assertEqual(load_device_policy(self.root)[0], ())

    def test_malformed_file_does_not_use_a_default_or_private_range_fallback(self):
        for value in ("bad-json", "[]", '{"allowed_networks":"10.0.0.0/8"}', '{"allowed_networks":[123]}'):
            self.config.write_text(value, encoding="utf-8")
            with self.assertRaises(ImproperlyConfigured):
                load_device_policy(self.root)
