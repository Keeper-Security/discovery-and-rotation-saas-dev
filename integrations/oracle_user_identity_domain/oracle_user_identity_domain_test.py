from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from plugin_dev.test_base import MockRecord
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from oracle_user_identity_domain import SaasPlugin
from oci.exceptions import ServiceError
from typing import Optional


class OracleIdentityPluginTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

        self.fake_prv_key = """
        -----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvqXo7bDhLtYGq
EMiNqDgytkvMICv+5fWa4YOH5j52bZAkHEhqnF2TQBaeR+QZAFzH+3RiWsaRzsvs
Mz8ZZRoq/wWjM8OytDCSfnDN
-----END PRIVATE KEY-----
        """.strip()

    def plugin(self,
               prior_password: Optional[Secret] = None,
               field_values: Optional[dict] = None,
               username: Optional[Secret] = None):

        if username is None:
            username = Secret("jdoe")

        user = SaasUser(
            username=username,
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        if field_values is None:
            field_values = {
                "Domain URL": "https://idcs-XXXXXX.identity.oraclecloud.com:443",
                "Admin OCID": "ocid1.user.oc1..aaaaaaaaXXXXXX",
                "Public Key Fingerprint": "99:99:99:99:99:99:99:99:99:99:99:99:99:99:99:99",
                "Private Key Content": self.fake_prv_key,
                "Tenancy OCID": "ocid1.tenancy.oc1..aaaaaaaaXXXXXX",
                "Home Region": "us-sanjose-1"
            }

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'Domain URL', 'value': [field_values.get("Domain URL")]},
                {'type': 'text', 'label': 'Admin OCID', 'value': [field_values.get("Admin OCID")]},
                {'type': 'text', 'label': 'Public Key Fingerprint',
                 'value': [field_values.get("Public Key Fingerprint")]},
                {'type': 'text', 'label': 'Private Key Content', 'value': [field_values.get("Private Key Content")]},
                {'type': 'text', 'label': 'Tenancy OCID', 'value': [field_values.get("Tenancy OCID")]},
                {'type': 'text', 'label': 'Home Region', 'value': [field_values.get("Home Region")]},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual(req_list[0], "oci")

    def test_change_password_success_username(self):
        """
        A happy path test using the username of user.
        """

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                plugin.change_password()

    def test_change_password_success_email(self):
        """
        A happy path test using the email address of user.
        """

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(username=Secret("jdoe@hotmail.com"))

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                plugin.change_password()

    def test_change_password_fail_no_user(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()

                mock_client_obj.patch_user.side_effect = [
                    ServiceError(
                        status=404,
                        code=None,
                        headers={},
                        message="Yeah not found"
                    )
                ]
                mock_client.return_value = mock_client_obj

                try:
                    plugin.change_password()
                    self.fail("should have failed")
                except Exception as err:
                    self.assertIn("The user was not found in the Identity Domain", str(err))

    def test_change_password_fail_general(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()

                mock_client_obj.patch_user.side_effect = [
                    ServiceError(
                        status=500,
                        code=None,
                        headers={},
                        message="I broke",
                    )
                ]
                mock_client.return_value = mock_client_obj

                try:
                    plugin.change_password()
                    self.fail("should have failed")
                except Exception as err:
                    self.assertIn("I broke", str(err))


    def test_pem_key_with_junk(self):
        """
        A happy path test where the downloded private key has OCI_API_KEY ayt the end.
        """

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(
                field_values = {
                    "Domain URL": "https://idcs-XXXXXX.identity.oraclecloud.com:443",
                    "Admin OCID": "ocid1.user.oc1..aaaaaaaaXXXXXX",
                    "Public Key Fingerprint": "99:99:99:99:99:99:99:99:99:99:99:99:99:99:99:99",
                    "Private Key Content": self.fake_prv_key + "\n" + "OCI_API_KEY",
                    "Tenancy OCID": "ocid1.tenancy.oc1..aaaaaaaaXXXXXX",
                    "Home Region": "us-sanjose-1"
                }
            )

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                plugin.change_password()

    def test_bad_admin_ocid(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(
                field_values={
                    "Domain URL": "https://idcs-XXXXXX.identity.oraclecloud.com:443",
                    "Admin OCID": "Admin@hotmail",
                    "Public Key Fingerprint": "99:99:99:99:99:99:99:99:99:99:99:99:99:99:99:99",
                    "Private Key Content": self.fake_prv_key,
                    "Tenancy OCID": "ocid1.tenancy.oc1..aaaaaaaaXXXXXX",
                    "Home Region": "us-sanjose-1"
                }
            )

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                try:
                    plugin.change_password()
                    self.fail("should have failed")
                except Exception as err:
                    self.assertIn("The format of the Admin OCID", str(err))

    def test_bad_key_content(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(
                field_values={
                    "Domain URL": "https://idcs-XXXXXX.identity.oraclecloud.com:443",
                    "Admin OCID": "ocid1.user.oc1..aaaaaaaaXXXXXX",
                    "Public Key Fingerprint": "99:99:99:99:99:99:99:99:99:99:99:99:99:99:99:99",
                    "Private Key Content": "BAD KEY",
                    "Tenancy OCID": "ocid1.tenancy.oc1..aaaaaaaaXXXXXX",
                    "Home Region": "us-sanjose-1"
                }
            )

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                try:
                    plugin.change_password()
                    self.fail("should have failed")
                except Exception as err:
                    self.assertIn("The value in Private Key Content", str(err))

    def test_bad_fingerprint(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(
                field_values={
                    "Domain URL": "https://idcs-XXXXXX.identity.oraclecloud.com:443",
                    "Admin OCID": "ocid1.user.oc1..aaaaaaaaXXXXXX",

                    # Missing a pair
                    "Public Key Fingerprint": "99:99:99:99:99:99:99:99:99:99:99:99:99:99:99",
                    "Private Key Content": self.fake_prv_key,
                    "Tenancy OCID": "ocid1.tenancy.oc1..aaaaaaaaXXXXXX",
                    "Home Region": "us-sanjose-1"
                }
            )

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                try:
                    plugin.change_password()
                    self.fail("should have failed")
                except Exception as err:
                    self.assertIn("The value in Public Key Fingerprint", str(err))

    def test_bad_tenancy_ocid(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(
                field_values={
                    "Domain URL": "https://idcs-XXXXXX.identity.oraclecloud.com:443",
                    "Admin OCID": "ocid1.user.oc1..aaaaaaaaXXXXXX",
                    "Public Key Fingerprint": "99:99:99:99:99:99:99:99:99:99:99:99:99:99:99:99",
                    "Private Key Content": self.fake_prv_key,
                    "Tenancy OCID": "cid1.tenancy.oc1..aaaaaaaaXXXXXX",
                    "Home Region": "us-sanjose-1"
                }
            )

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                try:
                    plugin.change_password()
                    self.fail("should have failed")
                except Exception as err:
                    self.assertIn("The format of the Tenancy OCID", str(err))

    def test_can_rollback_true(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()

                policy = MagicMock()
                policy.num_passwords_in_history = None

                resources = MagicMock()
                resources.resources = [
                    policy
                ]

                data = MagicMock()
                data.data = resources

                mock_client_obj.list_password_policies = MagicMock()
                mock_client_obj.list_password_policies.return_value = data

                mock_client.return_value = mock_client_obj

                self.assertTrue(plugin.can_rollback)

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()

                policy = MagicMock()
                policy.num_passwords_in_history = 0

                resources = MagicMock()
                resources.resources = [
                    policy
                ]

                data = MagicMock()
                data.data = resources

                mock_client_obj.list_password_policies = MagicMock()
                mock_client_obj.list_password_policies.return_value = data

                mock_client.return_value = mock_client_obj

                self.assertTrue(plugin.can_rollback)

    def test_can_rollback_false(self):

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()

                policy = MagicMock()
                policy.num_passwords_in_history = 5

                resources = MagicMock()
                resources.resources = [
                    policy
                ]

                data = MagicMock()
                data.data = resources

                mock_client_obj.list_password_policies = MagicMock()
                mock_client_obj.list_password_policies.return_value = data

                mock_client.return_value = mock_client_obj

                self.assertFalse(plugin.can_rollback)

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()

                resources = MagicMock()
                resources.resources = None

                data = MagicMock()
                data.data = resources

                mock_client_obj.list_password_policies = MagicMock()
                mock_client_obj.list_password_policies.return_value = data

                mock_client.return_value = mock_client_obj

                self.assertFalse(plugin.can_rollback)

    def test_rollback_success(self):
        """
        A happy path test using the username of user.
        """

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin(
                prior_password=Secret("OldPassword")
            )

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                plugin.rollback_password()

    def test_rollback_fail(self):
        """
        A happy path test using the username of user.
        """

        with patch("oci.config.validate_config") as mock_validate_config:
            mock_validate_config.return_value = None

            plugin = self.plugin()

            # Patch the module in the plugin
            with patch("oracle_user_identity_domain.IdentityDomainsClient") as mock_client:
                mock_client_obj = MagicMock()
                mock_client.return_value = mock_client_obj

                try:
                    plugin.rollback_password()
                    self.fail("should have gotten an exception")
                except Exception as err:
                    self.assertIn("The current password is not set", str(err))

