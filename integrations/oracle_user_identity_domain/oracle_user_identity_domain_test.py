from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch, mock_open
from tempfile import NamedTemporaryFile
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, ReturnCustomField
from kdnrm.exceptions import SaasException
from oracle_user_identity_domain import SaasPlugin, OracleClient
from typing import Optional


class OracleIdentityPluginTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None):
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [
                {"type": "fileRef", "value": ["FILE_UID"]}
            ],
            'custom': []
        }
        config_record.get_custom_field_value.side_effect = ["my.identity.oraclecloud.com"]
        config_record.download_file_by_title.return_value = "mock_token_content"

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        req_list = SaasPlugin.requirements()
        self.assertEqual(req_list, ["requests"])

    def test_config_schema(self):
        schema = SaasPlugin.config_schema()
        self.assertEqual(len(schema), 1)
        self.assertEqual(schema[0].id, "identity_domain")

    def test_change_password_success(self):
        plugin = self.plugin()

        with patch("builtins.open", mock_open(read_data="mock-access-token")), \
             patch.object(OracleClient, "get_ocid_by_username", return_value="mock-ocid"), \
             patch.object(OracleClient, "update_user_password") as mock_update:

            plugin.change_password()

            self.assertEqual(plugin._SaasPlugin__ocid, "mock-ocid")
            mock_update.assert_called_once()
            self.assertTrue(any("Oracle Identity Domain" in field.label for field in plugin.return_fields))
            self.assertTrue(plugin.can_rollback)

    def test_change_password_missing_token_file(self):
        plugin = self.plugin()
        plugin.config_record.dict['fields'] = []

        with self.assertRaises(SaasException) as cm:
            plugin.change_password()
        self.assertIn("Missing 'fileRef'", str(cm.exception))

    def test_change_password_http_error_on_ocid(self):
        plugin = self.plugin()

        with patch("builtins.open", mock_open(read_data="mock-access-token")), \
             patch.object(OracleClient, "get_ocid_by_username", side_effect=SaasException("Failure")), \
             patch.object(OracleClient, "update_user_password") as mock_update:

            with self.assertRaises(SaasException) as cm:
                plugin.change_password()
            self.assertIn("Failure", str(cm.exception))
            mock_update.assert_not_called()

    def test_rollback_password_success(self):
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        plugin._SaasPlugin__ocid = "user-ocid"
        plugin._client = MagicMock()

        plugin.rollback_password()
        plugin._client.update_user_password.assert_called_with(
            ocid="user-ocid", new_password="6"  # Adjust if needed
        )

    def test_rollback_password_without_ocid(self):
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        plugin._client = MagicMock()

        with self.assertRaises(SaasException) as cm:
            plugin.rollback_password()

        self.assertIn("OCID is not set", str(cm.exception))

    def test_rollback_password_without_prior_password(self):
        plugin = self.plugin()
        plugin._SaasPlugin__ocid = "user-ocid"
        plugin._client = MagicMock()

        with self.assertRaises(Exception):
            plugin.rollback_password()
    
    def test_get_ocid_by_username_user_not_found(self):
        client = OracleClient(identity_domain="my.identity.oraclecloud.com", access_token="token")
        with patch("oracle_user_identity_domain.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"Resources": []}
            mock_get.return_value = mock_response
            with self.assertRaises(SaasException) as cm:
                client.get_ocid_by_username("jdoe")
            self.assertIn("not found", str(cm.exception))
