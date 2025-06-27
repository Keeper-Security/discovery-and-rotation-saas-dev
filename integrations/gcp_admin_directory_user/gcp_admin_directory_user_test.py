from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from gcp_admin_directory_user import SaasPlugin, GCPClient
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from requests import Response

class GCPAdminDirectoryUserTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Secret = None):
        user = SaasUser(
            username=Secret("jdoe@company.com"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )
        config_record = MagicMock()
        config_record.dict = {
            'fields': [
                {"type": "fileRef", "value": ["service_account.json"]}
            ],
            'custom': [
                {'type': 'text', 'label': 'Super Admin Email', 'value': ['admin@company.com']}
            ]
        }
        config_record.title = 'GCP Admin Directory Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'
        config_record.get_custom_field_value.side_effect = [
            "admin@company.com"
        ]
        config_record.download_file_by_title.return_value = "JSON_DATA"
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test that the requirements method returns the correct list of requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(req_list, ["requests"])

    def test_change_password_success(self):
        """Test that the change_password method successfully changes the password."""
        plugin = self.plugin()
        with patch.object(GCPClient, "update_user_password") as mock_update_pw, \
            patch.object(GCPClient, "__init__", return_value=None) as mock_client_init:
            plugin._client = GCPClient("admin@company.com", "service_account.json")
            plugin.change_password()
            mock_update_pw.assert_called_once_with(
                user_email="jdoe@company.com",
                new_password="NewPassword123"
            )
            self.assertTrue(any(f.label == "Login URL" for f in plugin.return_fields))

    def test_missing_admin_email(self):
        """Test that an exception is raised if the admin email is missing."""
        plugin = self.plugin()
        plugin.get_config = MagicMock(return_value=None)
        with patch.object(GCPClient, "update_user_password"):
            with self.assertRaises(SaasException) as ctx:
                plugin.change_password()
            self.assertIn("Missing 'admin_email' field", str(ctx.exception))

    def test_missing_file_ref(self):
        """Test that an exception is raised if the fileRef field is missing."""
        plugin = self.plugin()
        plugin.config_record.dict['fields'] = []
        with self.assertRaises(SaasException) as ctx:
            plugin.change_password()
        self.assertIn("Missing 'fileRef' field", str(ctx.exception))

    def test_missing_username_or_password(self):
        """Test that an exception is raised if the username or new_password is missing."""
        plugin = self.plugin()
        plugin.user.username = Secret("")
        with patch.object(GCPClient, "__init__", return_value=None):
            plugin._client = GCPClient("admin@company.com", "service_account.json")
            with self.assertRaises(SaasException) as ctx:
                plugin.change_password()
            self.assertIn("Missing 'username' or 'new_password'", str(ctx.exception))

    def test_update_user_password_http_error(self):
        """Test that an exception is raised if the update_user_password fails."""
        plugin = self.plugin()
        with patch.object(GCPClient, "update_user_password", side_effect=SaasException("Failed to update password: 403")):
            plugin._client = GCPClient("admin@company.com", "service_account.json")
            with self.assertRaises(SaasException) as ctx:
                plugin.change_password()
            self.assertIn("Failed to update password: 403", str(ctx.exception))

    def test_rollback_password_success(self):
        """Test that the rollback_password method correctly rolls back the password."""
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        with patch.object(GCPClient, "update_user_password") as mock_update_pw:
            plugin._client = GCPClient("admin@company.com", "service_account.json")
            plugin.rollback_password()
            mock_update_pw.assert_called_once_with(
                user_email="jdoe@company.com",
                new_password="6"  # last char of "OldPassword456"
            )

    def test_rollback_password_http_error(self):
        """Test that an exception is raised if the rollback_password fails."""
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        with patch.object(GCPClient, "update_user_password", side_effect=SaasException("Failed to update password: 403")):
            plugin._client = GCPClient("admin@company.com", "service_account.json")
            with self.assertRaises(SaasException) as ctx:
                plugin.rollback_password()
            self.assertIn("Failed to rollback password change", str(ctx.exception))


class TestGCPClient(unittest.TestCase):

    def setUp(self):
        self.client = GCPClient("admin@company.com", "service_account.json")

    @patch("gcp_admin_directory_user.build")
    @patch("gcp_admin_directory_user.service_account")
    def test_update_user_password_success(self, mock_service_account, mock_build):
        mock_creds = MagicMock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_creds
        mock_creds.with_subject.return_value = mock_creds

        mock_service = MagicMock()
        mock_build.return_value = mock_service
        mock_users = MagicMock()
        mock_service.users.return_value = mock_users
        mock_update = MagicMock()
        mock_users.update.return_value = mock_update
        mock_update.execute.return_value = {"id": "user@company.com"}

        with patch.object(Log, "info") as mock_log_info:
            self.client.update_user_password("user@company.com", "newpass")
            mock_update.execute.assert_called_once()
            mock_log_info.assert_not_called()

    @patch("gcp_admin_directory_user.build")
    @patch("gcp_admin_directory_user.service_account")
    def test_update_user_password_request_exception(self, mock_service_account, mock_build):
        # Mock credentials and service
        mock_creds = MagicMock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_creds
        mock_creds.with_subject.return_value = mock_creds

        mock_service = MagicMock()
        mock_build.return_value = mock_service
        mock_users = MagicMock()
        mock_service.users.return_value = mock_users
        mock_update = MagicMock()
        mock_users.update.return_value = mock_update
        mock_update.execute.side_effect = Exception("Network error")

        with patch.object(Log, "error") as mock_log_error:
            with self.assertRaises(SaasException) as ctx:
                self.client.update_user_password("user@company.com", "newpass")
            self.assertIn("Failed to change password", str(ctx.exception))
            mock_log_error.assert_called()

if __name__ == "__main__":
    unittest.main()
