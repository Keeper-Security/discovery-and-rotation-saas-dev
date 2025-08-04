from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch

# Handle imports for both running from project root and from aws_secret_key directory
try:
    from integrations.aws_secret_key.aws_secret_key import SaasPlugin
except ModuleNotFoundError:
    from aws_secret_key import SaasPlugin

from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, AwsConfig, Field
from kdnrm.exceptions import SaasException
from plugin_dev.test_base import MockRecord
from typing import Optional
from datetime import datetime

# Mock ClientError for testing without requiring boto3
class MockClientError(Exception):
    """Mock ClientError for testing without boto3 dependency."""
    
    def __init__(self, error_response, operation_name):
        self.response = error_response
        self.operation_name = operation_name
        super().__init__()


class AwsSecretKeyTest(unittest.TestCase):
    """Test cases for AWS Secret Key SaaS Plugin."""

    def setUp(self):
        """Set up test environment before each test."""
        Log.init()
        Log.set_log_level("DEBUG")

    def create_plugin(self, 
                     username: str = "testuser",
                     client_id: Optional[str] = "AKIAIOSFODNN7EXAMPLE",
                     client_secret: Optional[str] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                     aws_region: str = "us-east-1",
                     provider_config: Optional[AwsConfig] = None,
                     user_field_value: Optional[str] = None,
                     prior_password: Optional[Secret] = None) -> SaasPlugin:
        """Create a SaasPlugin instance for testing.
        
        Args:
            username: IAM username for the plugin
            client_id: AWS Access Key ID
            client_secret: AWS Secret Access Key
            aws_region: AWS region
            provider_config: Optional AWS provider configuration
            user_field_value: Value for aws_access_key_id user field
            prior_password: Prior password for the user
            
        Returns:
            Configured SaasPlugin instance
        """
        # Create user with fields
        user = SaasUser(
            username=Secret("testuser") if username else Secret(None),
            new_password=Secret("NewSecretKey123"),
            prior_password=prior_password,
            fields=[]
        )
        
        # Add user fields if specified
        if user_field_value:
            user.fields = [Field(
                type="text",
                label="aws_access_key_id",
                values=[user_field_value]
            )]

        # Create configuration record
        config_fields = []
        if username is not None:
            config_fields.append({
                'type': 'text', 
                'label': 'IAM Username', 
                'value': [username]
            })
        if client_id is not None:
            config_fields.append({
                'type': 'secret', 
                'label': 'Client ID', 
                'value': [client_id]
            })
        if client_secret is not None:
            config_fields.append({
                'type': 'secret', 
                'label': 'Client Secret', 
                'value': [client_secret]
            })
        if aws_region is not None:
            config_fields.append({
                'type': 'text', 
                'label': 'AWS Region', 
                'value': [aws_region]
            })

        config_record = MockRecord(custom=config_fields)

        return SaasPlugin(
            user=user, 
            config_record=config_record, 
            provider_config=provider_config
        )

    def test_requirements(self):
        """Test that the plugin returns the correct requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("boto3", req_list[0])

    def test_config_schema(self):
        """Test that config schema returns correct items."""
        schema = SaasPlugin.config_schema()
        
        self.assertEqual(4, len(schema))
        
        # Verify specific config items exist
        config_ids = [item.id for item in schema]
        expected_ids = ["username", "client_id", "client_secret", "aws_region"]
        
        for expected_id in expected_ids:
            self.assertIn(expected_id, config_ids)
        
        # Verify username is required
        username_config = next(item for item in schema if item.id == "username")
        self.assertTrue(username_config.required)

    @patch("boto3.client")
    def test_change_password_success_basic(self, mock_client):
        """Test successful password change with basic configuration."""
        plugin = self.create_plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")
        mock_iam = MagicMock()
        mock_client.return_value = mock_iam
        
        # Mock successful AWS responses
        mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
        mock_iam.create_access_key.return_value = {
            'AccessKey': {
                'AccessKeyId': 'AKIANEWEXAMPLE1234',
                'SecretAccessKey': 'newSecretAccessKey12345'
            }
        }

        plugin.change_password()

        # Verify AWS API calls
        mock_iam.get_user.assert_called_once_with(UserName="testuser")
        mock_iam.list_access_keys.assert_called_once_with(UserName="testuser")
        mock_iam.create_access_key.assert_called_once_with(UserName="testuser")
        mock_iam.delete_access_key.assert_not_called()

        # Verify client initialization
        mock_client.assert_called_once_with(
            "iam",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region_name="us-east-1"
        )

        # Verify return fields were set
        self.assertEqual(2, len(plugin.return_fields))
        field_labels = [field.label for field in plugin.return_fields]
        self.assertIn("aws_access_key_id", field_labels)
        self.assertIn("aws_secret_access_key", field_labels)
        
        self.assertFalse(plugin.can_rollback)

    @patch("boto3.client")
    def test_change_password_with_provider_config(self, mock_client):
        """Test successful password change using AWS provider configuration."""
        aws_config = AwsConfig(
            aws_access_key_id=Secret("AKIAIOSFODNN7EXAMPLE"),
            aws_secret_access_key=Secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            region_names=["us-west-2", "us-east-2"]
        )

        plugin = self.create_plugin(
            aws_region="us-west-2",
            provider_config=aws_config,
            user_field_value="AKIAIOSFODNN7EXAMPLE"
        )

        mock_iam = MagicMock()
        mock_client.return_value = mock_iam
        
        # Mock successful responses
        mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
        mock_iam.create_access_key.return_value = {
            'AccessKey': {
                'AccessKeyId': 'AKIANEWPROVIDER456',
                'SecretAccessKey': 'newProviderSecretKey789'
            }
        }

        plugin.change_password()

        # Verify client was created with provider config credentials
        mock_client.assert_called_once_with(
            "iam",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region_name="us-west-2"
        )

    def test_change_password_missing_username(self):
        """Test failure when username is missing from config."""
        with self.assertRaises(SaasException) as context:
            plugin = self.create_plugin(username=None)
            plugin.change_password()
        
        # Match the actual error message from the plugin
        self.assertIn("field IAM Username is required", str(context.exception))

    @patch("boto3.client")
    def test_change_password_user_not_found(self, mock_client):
        """Test failure when IAM user doesn't exist."""
        # Patch ClientError in the module where it's used
        with patch('aws_secret_key.ClientError', MockClientError):
            with patch('integrations.aws_secret_key.aws_secret_key.ClientError', MockClientError):
                plugin = self.create_plugin()
                mock_iam = MagicMock()
                mock_client.return_value = mock_iam
                
                # Mock user not found error
                mock_iam.get_user.side_effect = MockClientError(
                    {
                        "Error": {
                            "Code": "NoSuchEntity",
                            "Message": "User does not exist.",
                        }
                    }, operation_name="GetUser"
                )

                with self.assertRaises(SaasException) as context:
                    plugin.change_password()
                
                self.assertIn("does not exist", str(context.exception))

    @patch("boto3.client")
    def test_change_password_with_key_deletion(self, mock_client):
        """Test successful password change when user has 2 keys (requires deletion)."""
        plugin = self.create_plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")
        mock_iam = MagicMock()
        mock_client.return_value = mock_iam
        
        # Mock successful user check
        mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
        
        # Mock user already has 2 access keys (AWS limit)
        mock_iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'CreateDate': datetime(2023, 1, 1)},
                {'AccessKeyId': 'AKIAIOSFODNN7DIFFERENT', 'CreateDate': datetime(2023, 1, 2)}
            ]
        }
        
        # Mock successful key creation after deletion
        mock_iam.create_access_key.return_value = {
            'AccessKey': {
                'AccessKeyId': 'AKIANEWREPLACEMENT01',
                'SecretAccessKey': 'newReplacementSecretKey123'
            }
        }
        
        plugin.change_password()
        
        # Verify old key was deleted and new key was created
        mock_iam.delete_access_key.assert_called_once_with(
            UserName="testuser", 
            AccessKeyId="AKIAIOSFODNN7EXAMPLE"
        )
        mock_iam.create_access_key.assert_called_once_with(UserName="testuser")

    @patch("boto3.client")
    def test_change_password_create_key_limit_exceeded(self, mock_client):
        """Test handling of AWS limit exceeded error during key creation."""
        # Patch ClientError in the module where it's used
        with patch('aws_secret_key.ClientError', MockClientError):
            with patch('integrations.aws_secret_key.aws_secret_key.ClientError', MockClientError):
                plugin = self.create_plugin()
                mock_iam = MagicMock()
                mock_client.return_value = mock_iam
                
                # Mock successful user check and empty key list
                mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
                mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
                
                # Mock create access key limit exceeded
                mock_iam.create_access_key.side_effect = MockClientError(
                    {
                        "Error": {
                            "Code": "LimitExceeded",
                            "Message": "Cannot exceed quota for AccessKeysPerUser",
                        }
                    }, operation_name="CreateAccessKey"
                )

                with self.assertRaises(SaasException) as context:
                    plugin.change_password()
                
                self.assertIn("Access key limit exceeded", str(context.exception))

    @patch.object(SaasPlugin, '_using_session')
    def test_change_password_missing_access_key_id_no_session(self, mock_session):
        """Test failure when AWS access key ID is missing and no session available."""
        mock_session.return_value = None

        with self.assertRaises(SaasException) as context:
            plugin = self.create_plugin(client_id=None)
            plugin.change_password()
        
        # The expected error message based on the actual implementation
        self.assertIn("Client ID", str(context.exception))

    @patch.object(SaasPlugin, '_using_session')
    def test_change_password_missing_secret_access_key_no_session(self, mock_session):
        """Test failure when AWS secret access key is missing and no session available."""
        mock_session.return_value = None

        with self.assertRaises(SaasException) as context:
            plugin = self.create_plugin(client_secret=None)
            plugin.change_password()
        
        # The expected error message based on the actual implementation
        self.assertIn("Client Secret", str(context.exception))

    def test_rollback_behavior(self):
        """Test rollback behavior (disabled in current implementation)."""
        plugin = self.create_plugin(prior_password=Secret("OldSecretKey123"))
        
        # Rollback should just log that it's not supported and not crash
        plugin.rollback_password()
        
        # Verify rollback capability
        self.assertFalse(plugin.can_rollback)

    @patch("boto3.Session")
    def test_using_session_with_credentials(self, mock_session_class):
        """Test session detection when credentials are available."""
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = MagicMock()  # Credentials exist
        mock_session_class.return_value = mock_session
        
        # Test the static method directly
        result = SaasPlugin._using_session()  # noqa: SLF001
        self.assertIsNotNone(result)
        self.assertEqual(result, mock_session)

    @patch("boto3.Session")
    def test_using_session_without_credentials(self, mock_session_class):
        """Test session detection when no credentials are available."""
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None  # No credentials
        mock_session_class.return_value = mock_session
        
        # Test the static method directly
        result = SaasPlugin._using_session()  # noqa: SLF001
        self.assertIsNone(result)

    def test_validation_edge_cases(self):
        """Test various validation edge cases."""
        # Test invalid username formats
        with self.assertRaises(SaasException):
            plugin = self.create_plugin(username="")
            plugin.change_password()

        # Test invalid region format
        with self.assertRaises(SaasException):
            plugin = self.create_plugin(aws_region="invalid-region-format")
            plugin.change_password()

        # Test invalid access key ID format
        with self.assertRaises(SaasException):
            plugin = self.create_plugin(client_id="INVALID_KEY_ID")
            plugin.change_password()

    @patch("boto3.client")
    def test_change_password_missing_old_access_key_field(self, mock_client):
        """Test handling when user has 2 keys but no old access key field."""
        plugin = self.create_plugin()  # No user_field_value
        mock_iam = MagicMock()
        mock_client.return_value = mock_iam
        
        # Mock user with 2 existing keys
        mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
        mock_iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {'AccessKeyId': 'AKIAKEY1EXAMPLE123', 'CreateDate': datetime(2023, 1, 1)},
                {'AccessKeyId': 'AKIAKEY2EXAMPLE456', 'CreateDate': datetime(2023, 1, 2)}
            ]
        }
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("AWS Access Key ID is required in user fields", str(context.exception))


if __name__ == '__main__':
    unittest.main()
