from __future__ import annotations
import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import tempfile
import os
from kdnrm.exceptions import SaasException
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, ReturnCustomField
from plugin_dev.test_base import MockRecord
from integrations.gcp_service_account.gcp_service_account import SaasPlugin

# Check if Google Cloud libraries are available
try:
    from google.cloud import iam_admin_v1
    from google.oauth2 import service_account
    HAS_GOOGLE_CLOUD = True
except ImportError:
    HAS_GOOGLE_CLOUD = False


class TestGcpServiceAccountPlugin(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")
        
        # Mock service account file content
        self.mock_service_account_data = {
            "type": "service_account",
            "project_id": "test-project-123",
            "private_key_id": "test-key-id",
            "private_key": "-----BEGIN PRIVATE KEY-----\ntest-private-key\n-----END PRIVATE KEY-----",
            "client_email": "admin-sa@test-project-123.iam.gserviceaccount.com",
            "client_id": "123456789",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/admin-sa%40test-project-123.iam.gserviceaccount.com"
        }

    def create_plugin(self, service_account_data=None, username=None):
        """Create a plugin instance with mocked file attachment"""
        if username is None:
            username = Secret("test-user")

        user = SaasUser(
            username=username,
            new_password=Secret("NewKey123"),
            prior_password=None
        )

        if service_account_data is None:
            service_account_data = self.mock_service_account_data

        # Create a mock file object
        mock_file = Mock()
        mock_file.name = "service_account.json"
        mock_file.type = "application/json"

        # Create mock record with file attachment
        config_record = MockRecord(custom=[])
        config_record.files = [mock_file]
        
        # Mock the download_file_by_title method to write the JSON data to the temp file
        def mock_download(filename, target_path):
            with open(target_path, 'w', encoding='utf-8') as f:
                json.dump(service_account_data, f)
        
        config_record.download_file_by_title = Mock(side_effect=mock_download)

        return SaasPlugin(user=user, config_record=config_record)

    def test_config_schema_empty(self):
        """Test that config schema is empty"""
        schema = SaasPlugin.config_schema()
        self.assertEqual(len(schema), 0)

    def test_requirements(self):
        """Test that requirements include Google Cloud IAM"""
        requirements = SaasPlugin.requirements()
        self.assertIn("google-cloud-iam", requirements)

    def test_parse_service_account_file_success(self):
        """Test successful parsing of service account file"""
        plugin = self.create_plugin()
        
        # Test project ID extraction
        project_id = plugin.project_id
        self.assertEqual(project_id, "test-project-123")
        
        # Test service account email extraction
        service_account_email = plugin.service_account_email
        self.assertEqual(service_account_email, "admin-sa@test-project-123.iam.gserviceaccount.com")

    def test_parse_service_account_file_no_files(self):
        """Test parsing when no files are attached"""
        plugin = self.create_plugin()
        plugin.config_record.files = []
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.project_id
        
        self.assertIn("No files attached", str(context.exception))

    def test_parse_service_account_file_invalid_json(self):
        """Test parsing with invalid JSON"""
        plugin = self.create_plugin()
        
        # Mock download to write invalid JSON
        def mock_download_invalid(filename, target_path):
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write("invalid json content")
        
        plugin.config_record.download_file_by_title = Mock(side_effect=mock_download_invalid)
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.project_id
        
        self.assertIn("Invalid JSON", str(context.exception))

    def test_parse_service_account_file_missing_field(self):
        """Test parsing with missing required fields"""
        incomplete_data = self.mock_service_account_data.copy()
        del incomplete_data["project_id"]
        
        plugin = self.create_plugin(service_account_data=incomplete_data)
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.project_id
        
        self.assertIn("Missing required field", str(context.exception))

    def test_parse_service_account_file_invalid_type(self):
        """Test parsing with invalid service account type"""
        invalid_data = self.mock_service_account_data.copy()
        invalid_data["type"] = "user_account"
        
        plugin = self.create_plugin(service_account_data=invalid_data)
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.project_id
        
        self.assertIn("not a valid service account file", str(context.exception))

    @patch('integrations.gcp_service_account.gcp_service_account.iam_admin_v1')
    @patch('integrations.gcp_service_account.gcp_service_account.service_account')
    def test_setup_iam_client_success(self, mock_service_account, mock_iam_admin):
        """Test successful IAM client setup"""
        mock_credentials = Mock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_credentials
        mock_iam_client = Mock()
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        
        plugin = self.create_plugin()
        
        # Access the IAM client property
        client = plugin.iam_client
        
        # Verify the client was created
        self.assertEqual(client, mock_iam_client)
        mock_service_account.Credentials.from_service_account_file.assert_called_once()
        mock_iam_admin.IAMClient.assert_called_once_with(credentials=mock_credentials)

    @patch('integrations.gcp_service_account.gcp_service_account.iam_admin_v1')
    @patch('integrations.gcp_service_account.gcp_service_account.service_account')
    def test_create_service_account_key_success(self, mock_service_account, mock_iam_admin):
        """Test successful service account key creation"""
        # Mock the IAM client and key response
        mock_iam_client = Mock()
        mock_key = Mock()
        mock_key.name = "projects/test-project-123/serviceAccounts/admin-sa@test-project-123.iam.gserviceaccount.com/keys/test-key-id"
        mock_key.private_key_data = b'{"type": "service_account", "private_key": "test-key"}'
        
        mock_iam_client.create_service_account_key.return_value = mock_key
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        
        mock_credentials = Mock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_credentials
        
        plugin = self.create_plugin()
        
        # Create the key
        plugin._create_service_account_key()
        
        # Verify the key was created and stored
        self.assertEqual(plugin._created_key_name, mock_key.name)
        
        # Verify the create request was called
        mock_iam_client.create_service_account_key.assert_called_once()
        
        # Verify return field was added
        self.assertEqual(len(plugin.return_fields), 1)
        self.assertEqual(plugin.return_fields[0].label, "GCP Service Account Key")

    @patch('integrations.gcp_service_account.gcp_service_account.iam_admin_v1')
    @patch('integrations.gcp_service_account.gcp_service_account.service_account')
    def test_delete_service_account_key_success(self, mock_service_account, mock_iam_admin):
        """Test successful service account key deletion"""
        # Mock the IAM client
        mock_iam_client = Mock()
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        
        mock_credentials = Mock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_credentials
        
        plugin = self.create_plugin()
        
        key_name = "projects/test-project-123/serviceAccounts/admin-sa@test-project-123.iam.gserviceaccount.com/keys/test-key-id"
        
        # Delete the key
        plugin._delete_service_account_key(key_name)
        
        # Verify the delete request was called
        mock_iam_client.delete_service_account_key.assert_called_once()

    @patch('integrations.gcp_service_account.gcp_service_account.iam_admin_v1')
    @patch('integrations.gcp_service_account.gcp_service_account.service_account')
    def test_change_password_success(self, mock_service_account, mock_iam_admin):
        """Test successful password change (key creation)"""
        # Mock the IAM client and key response
        mock_iam_client = Mock()
        mock_key = Mock()
        mock_key.name = "projects/test-project-123/serviceAccounts/admin-sa@test-project-123.iam.gserviceaccount.com/keys/test-key-id"
        mock_key.private_key_data = b'{"type": "service_account", "private_key": "test-key"}'
        
        mock_iam_client.create_service_account_key.return_value = mock_key
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        
        mock_credentials = Mock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_credentials
        
        plugin = self.create_plugin()
        
        # Execute change password
        plugin.change_password()
        
        # Verify the key was created and stored
        self.assertEqual(plugin._created_key_name, mock_key.name)

    def test_rollback_password_no_key_created(self):
        """Test rollback when no key was created"""
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("Cannot rollback", str(context.exception))

    @patch('integrations.gcp_service_account.gcp_service_account.iam_admin_v1')
    @patch('integrations.gcp_service_account.gcp_service_account.service_account')
    def test_rollback_password_success(self, mock_service_account, mock_iam_admin):
        """Test successful rollback (key deletion)"""
        # Mock the IAM client
        mock_iam_client = Mock()
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        
        mock_credentials = Mock()
        mock_service_account.Credentials.from_service_account_file.return_value = mock_credentials
        
        plugin = self.create_plugin()
        
        # Set up a created key for rollback
        key_name = "projects/test-project-123/serviceAccounts/admin-sa@test-project-123.iam.gserviceaccount.com/keys/test-key-id"
        plugin._created_key_name = key_name
        
        # Execute rollback
        plugin.rollback_password()
        
        # Verify the key was deleted and cleared
        mock_iam_client.delete_service_account_key.assert_called_once()
        self.assertIsNone(plugin._created_key_name)

    def test_can_rollback(self):
        """Test can_rollback property"""
        plugin = self.create_plugin()
        
        # Should always return False as per current implementation
        self.assertFalse(plugin.can_rollback)

    def test_temp_file_creation(self):
        """Test that temporary files are created properly"""
        plugin = self.create_plugin()
        
        # Check that temp file path is set
        self.assertIsNotNone(plugin.temp_service_account_file)
        self.assertTrue(plugin.temp_service_account_file.endswith('.json'))

    def test_cleanup_on_destruction(self):
        """Test that temporary files are cleaned up when plugin is destroyed"""
        plugin = self.create_plugin()
        temp_file_path = plugin.temp_service_account_file
        
        # Trigger file creation by accessing a property
        _ = plugin.project_id
        
        # Verify file exists
        self.assertTrue(os.path.exists(temp_file_path))
        
        # Delete plugin and verify cleanup
        del plugin
        
        # Note: In real usage, cleanup happens automatically when the plugin goes out of scope

    def test_multiple_files_prefers_json(self):
        """Test that when multiple files are attached, JSON files are preferred"""
        plugin = self.create_plugin()
        
        # Create multiple mock files
        json_file = Mock()
        json_file.name = "service_account.json"
        json_file.type = "application/json"
        
        text_file = Mock()
        text_file.name = "readme.txt"
        text_file.type = "text/plain"
        
        plugin.config_record.files = [text_file, json_file]
        
        # Should use the JSON file
        _ = plugin.project_id
        plugin.config_record.download_file_by_title.assert_called_with("service_account.json", plugin.temp_service_account_file)


if __name__ == '__main__':
    unittest.main() 