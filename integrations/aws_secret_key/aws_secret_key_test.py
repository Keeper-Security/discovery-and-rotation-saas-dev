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
from kdnrm.saas_type import SaasUser, AwsConfig
from kdnrm.exceptions import SaasException
from botocore.exceptions import ClientError
from plugin_dev.test_base import MockRecord
from typing import Optional, Any, List
from datetime import datetime


class AwsSecretKeyTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None,
               provider_config: Optional[Any] = None,
               field_values: List[Any] = None,
               user_field_value: Optional[str] = None):

        if field_values is None:
            field_values = [
                "testuser",  # username
                "AKIAIOSFODNN7EXAMPLE",  # client_id (valid 20-char AWS access key)
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # client_secret
                "us-east-1"  # aws_region
            ]

        # Create a mock user
        user = SaasUser(
            username=Secret("testuser"),
            new_password=Secret("NewSecretKey123"),
            prior_password=prior_password
        )
        
        # Create mock user fields for the old access key
        if user_field_value:
            # Create a simple mock field object that behaves properly
            class MockField:
                def __init__(self, label, values):
                    self.label = label
                    self.values = values
            
            user.fields = [MockField("aws_access_key_id", [user_field_value])]
        else:
            user.fields = []

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'IAM Username', 'value': [field_values[0]]},
                {'type': 'secret', 'label': 'Client ID', 'value': [field_values[1]]},
                {'type': 'secret', 'label': 'Client Secret', 'value': [field_values[2]]},
                {'type': 'text', 'label': 'AWS Region', 'value': [field_values[3]]},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record, provider_config=provider_config)

    def test_requirements(self):
        """
        Check if requirement returns the correct module.
        """
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("boto3", req_list[0])

    def test_change_password_success(self):
        """
        A happy path test.
        Everything works and the rotation is a success.
        """
        plugin = self.plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")

        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Mock successful user check
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            
            # Mock list access keys (user has no existing keys)
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': []
            }
            
            # Mock create access key
            mock_iam.create_access_key.return_value = {
                'AccessKey': {
                    'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                    'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                }
            }

            plugin.change_password()

            # Verify the correct IAM calls were made
            mock_iam.get_user.assert_called_once_with(UserName="testuser")
            mock_iam.list_access_keys.assert_called_once_with(UserName="testuser")
            mock_iam.create_access_key.assert_called_once_with(UserName="testuser")
            # No delete call expected when user has < 2 keys
            mock_iam.delete_access_key.assert_not_called()

            # Verify client creation
            args, kwargs = mock_client.call_args
            self.assertEqual("iam", args[0])
            self.assertEqual("AKIAIOSFODNN7EXAMPLE", kwargs["aws_access_key_id"])
            self.assertEqual("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", kwargs["aws_secret_access_key"])
            self.assertEqual("us-east-1", kwargs["region_name"])

        self.assertFalse(plugin.can_rollback)

    def test_change_password_provider_success(self):
        """
        A happy path test using AWS creds from PAM AWS configuration record.
        """
        aws_config = AwsConfig(
            aws_access_key_id=Secret("AKIAIOSFODNN7EXAMPLE"),
            aws_secret_access_key=Secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            region_names=["us-west-2", "us-east-2"]
        )

        plugin = self.plugin(
            field_values=["testuser", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-west-2"], 
            provider_config=aws_config,
            user_field_value="AKIAIOSFODNN7EXAMPLE"
        )

        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Mock successful responses
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
            mock_iam.create_access_key.return_value = {
                'AccessKey': {
                    'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                    'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                }
            }

            plugin.change_password()

            # Verify client creation with PAM config
            args, kwargs = mock_client.call_args
            self.assertEqual("iam", args[0])
            self.assertEqual("AKIAIOSFODNN7EXAMPLE", kwargs["aws_access_key_id"])
            self.assertEqual("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", kwargs["aws_secret_access_key"])
            self.assertEqual("us-west-2", kwargs["region_name"])

    def test_change_password_missing_username(self):
        """Test failure when username is missing."""
        try:
            plugin = self.plugin(field_values=[None, "AKIAIOSFODNN7EXAMPLE", "client_secret", "us-east-1"])
            plugin.change_password()
            self.fail("should have failed")
        except SaasException as err:
            self.assertIn("IAM Username is required", str(err))

    def test_change_password_user_not_found(self):
        """Test failure when IAM user doesn't exist."""
        plugin = self.plugin()

        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Mock user not found
            mock_iam.get_user.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "NoSuchEntity",
                        "Message": "User does not exist.",
                    }
                }, operation_name="GetUser"
            )

            try:
                plugin.change_password()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("does not exist", str(err))

    def test_change_password_access_key_limit_exceeded(self):
        """Test failure when access key limit is exceeded."""
        plugin = self.plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")

        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Mock successful user check
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            
            # Mock user already has 2 access keys (AWS limit)
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'CreateDate': datetime(2023, 1, 1)},
                    {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'CreateDate': datetime(2023, 1, 2)}
                ]
            }
            
            # Mock create access key with actual values
            mock_iam.create_access_key.return_value = {
                'AccessKey': {
                    'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                    'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                }
            }
            
            # This test expects the method to complete successfully since it will delete the old key first
            plugin.change_password()
            
            # Verify deletion and creation happened
            mock_iam.delete_access_key.assert_called_once()
            mock_iam.create_access_key.assert_called_once()

    def test_change_password_create_key_limit_exceeded(self):
        """Test handling of AWS limit exceeded error during key creation."""
        plugin = self.plugin()

        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Mock successful user check and empty key list
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
            
            # Mock create access key limit exceeded
            mock_iam.create_access_key.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "LimitExceeded",
                        "Message": "Cannot exceed quota for AccessKeysPerUser",
                    }
                }, operation_name="CreateAccessKey"
            )

            try:
                plugin.change_password()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access key limit exceeded", str(err))

    def test_change_password_missing_access_key_id_no_session(self):
        """Test failure when AWS access key ID is missing and no session available."""
        # Prevent using session credentials
        with patch.object(SaasPlugin, '_using_session') as mock_session:
            mock_session.return_value = None

            try:
                plugin = self.plugin(field_values=["testuser", None, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1"])
                plugin.change_password()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("AWS Access Key ID is blank", str(err))

    def test_change_password_missing_secret_access_key_no_session(self):
        """Test failure when AWS secret access key is missing and no session available."""
        # Prevent using session credentials
        with patch.object(SaasPlugin, '_using_session') as mock_session:
            mock_session.return_value = None

            try:
                plugin = self.plugin(field_values=["testuser", "AKIAIOSFODNN7EXAMPLE", None, "us-east-1"])
                plugin.change_password()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("field Client Secret is required", str(err))

    def test_rollback_success(self):
        """Test rollback behavior (now disabled)."""
        plugin = self.plugin(prior_password=Secret("OldSecretKey123"))
        
        # Rollback should just log that it's not supported
        plugin.rollback_password()
        
        # No AWS calls should be made since rollback is disabled
        # This test just verifies it doesn't crash

    def test_rollback_no_old_key_id(self):
        """Test rollback when no old key ID is stored."""
        plugin = self.plugin(prior_password=Secret("OldSecretKey123"))
        
        # No old access key ID stored
        plugin._old_access_key_id = None

        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam

            # Should complete without error but not make any delete calls
            plugin.rollback_password()
            
            mock_iam.delete_access_key.assert_not_called()

    def test_using_session_with_credentials(self):
        """Test session detection when credentials are available."""
        with patch("boto3.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = MagicMock()  # Credentials exist
            mock_session_class.return_value = mock_session
            
            result = SaasPlugin._using_session()
            self.assertIsNotNone(result)
            self.assertEqual(result, mock_session)

    def test_using_session_without_credentials(self):
        """Test session detection when no credentials are available."""
        with patch("boto3.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None  # No credentials
            mock_session_class.return_value = mock_session
            
            result = SaasPlugin._using_session()
            self.assertIsNone(result)

    def test_config_schema(self):
        """Test that config schema returns correct items."""
        schema = SaasPlugin.config_schema()
        
        # Verify we have the expected number of config items
        self.assertEqual(4, len(schema))
        
        # Verify specific config items exist
        config_ids = [item.id for item in schema]
        expected_ids = ["username", "client_id", "client_secret", "aws_region"]
        
        for expected_id in expected_ids:
            self.assertIn(expected_id, config_ids)
        
        # Verify username is required
        username_config = next(item for item in schema if item.id == "username")
        self.assertTrue(username_config.required)


if __name__ == '__main__':
    unittest.main()
