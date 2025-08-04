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

    def test_rotate_api_key_success(self):
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
                    'AccessKeyId': 'AKIANEWKEY12345678',
                    'SecretAccessKey': 'newSecretKey+AbCdEfGhIjKlMnOpQrStUvWxYz123'
                }
            }

            plugin.rotate_api_key()

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

            # Verify return fields were set
            self.assertEqual(2, len(plugin.return_fields))
            field_labels = [field.label for field in plugin.return_fields]
            self.assertIn("aws_access_key_id", field_labels)
            self.assertIn("aws_secret_access_key", field_labels)

        self.assertFalse(plugin.can_rollback)

    def test_rotate_api_key_provider_success(self):
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
                    'AccessKeyId': 'AKIANEWPROVIDER456',
                    'SecretAccessKey': 'newProviderSecretKey789'
                }
            }

            plugin.rotate_api_key()

            # Verify client creation with PAM config
            args, kwargs = mock_client.call_args
            self.assertEqual("iam", args[0])
            self.assertEqual("AKIAIOSFODNN7EXAMPLE", kwargs["aws_access_key_id"])
            self.assertEqual("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", kwargs["aws_secret_access_key"])
            self.assertEqual("us-west-2", kwargs["region_name"])

    def test_rotate_api_key_missing_username(self):
        """Test failure when username is missing."""
        try:
            plugin = self.plugin(field_values=[None, "AKIAIOSFODNN7EXAMPLE", "client_secret", "us-east-1"])
            plugin.rotate_api_key()
            self.fail("should have failed")
        except SaasException as err:
            self.assertIn("field IAM Username is required", str(err))

    def test_rotate_api_key_user_not_found(self):
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
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("does not exist", str(err))

    def test_rotate_api_key_with_key_deletion(self):
        """Test successful rotation when user has 2 keys (requires deletion)."""
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
                    {'AccessKeyId': 'AKIAIOSFODNN7DIFFERENT', 'CreateDate': datetime(2023, 1, 2)}
                ]
            }
            
            # Mock create access key with actual values
            mock_iam.create_access_key.return_value = {
                'AccessKey': {
                    'AccessKeyId': 'AKIANEWREPLACEMENT01',
                    'SecretAccessKey': 'newReplacementSecretKey123'
                }
            }
            
            # This test expects the method to complete successfully since it will delete the old key first
            plugin.rotate_api_key()
            
            # Verify deletion and creation happened
            mock_iam.delete_access_key.assert_called_once_with(
                UserName="testuser", 
                AccessKeyId="AKIAIOSFODNN7EXAMPLE"
            )
            mock_iam.create_access_key.assert_called_once_with(UserName="testuser")

    def test_rotate_api_key_create_key_limit_exceeded(self):
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
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access key limit exceeded", str(err))

    def test_rotate_api_key_missing_access_key_id_no_session(self):
        """Test failure when AWS access key ID is missing and no session available."""
        # Prevent using session credentials
        with patch.object(SaasPlugin, '_using_session') as mock_session:
            mock_session.return_value = None

            try:
                plugin = self.plugin(field_values=["testuser", None, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1"])
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("field Client ID is required", str(err))

    def test_rotate_api_key_missing_secret_access_key_no_session(self):
        """Test failure when AWS secret access key is missing and no session available."""
        # Prevent using session credentials
        with patch.object(SaasPlugin, '_using_session') as mock_session:
            mock_session.return_value = None

            try:
                plugin = self.plugin(field_values=["testuser", "AKIAIOSFODNN7EXAMPLE", None, "us-east-1"])
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("field Client Secret is required", str(err))

    def test_rollback_api_key_behavior(self):
        """Test rollback behavior (now disabled)."""
        plugin = self.plugin(prior_password=Secret("OldSecretKey123"))
        
        # Rollback should just log that it's not supported
        plugin.rollback_api_key()
        
        # No AWS calls should be made since rollback is disabled
        # This test just verifies it doesn't crash
        
        # Verify rollback capability
        self.assertFalse(plugin.can_rollback)

    def test_rotate_api_key_missing_old_access_key_field(self):
        """Test handling when user has 2 keys but no old access key field."""
        plugin = self.plugin()  # No user_field_value

        with patch("boto3.client") as mock_client:
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
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("AWS Access Key ID is required in user fields", str(err))

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

    def test_validation_edge_cases(self):
        """Test various validation edge cases."""
        # Test empty username (caught during plugin initialization)
        try:
            plugin = self.plugin(field_values=[None, "AKIAIOSFODNN7EXAMPLE", "secret", "us-east-1"])
            plugin.rotate_api_key()
            self.fail("should have failed")
        except SaasException as err:
            self.assertIn("field IAM Username is required", str(err))

        # Test invalid region format during rotation
        plugin = self.plugin(field_values=["testuser", "AKIAIOSFODNN7EXAMPLE", "secret", "invalid-region"])
        try:
            plugin.rotate_api_key()
            self.fail("should have failed")
        except SaasException as err:
            self.assertIn("Invalid AWS region format", str(err))

        # Test invalid access key ID format during rotation
        plugin = self.plugin(field_values=["testuser", "INVALID_KEY_ID", "secret", "us-east-1"])
        try:
            plugin.rotate_api_key()
            self.fail("should have failed")
        except SaasException as err:
            self.assertIn("Access Key ID", str(err))

    def test_username_validation_comprehensive(self):
        """Test comprehensive username validation scenarios."""
        plugin = self.plugin()
        
        # Test empty username string 
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': '',
                'client_id': 'AKIAIOSFODNN7EXAMPLE',
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Username cannot be empty", str(err))

        # Test username too long (>128 characters)
        long_username = "a" * 129
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': long_username,
                'client_id': 'AKIAIOSFODNN7EXAMPLE',
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Username must be between 1 and 128 characters", str(err))

        # Test invalid username characters
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'user@#$%',
                'client_id': 'AKIAIOSFODNN7EXAMPLE',
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Username contains invalid characters", str(err))

    def test_access_key_validation_comprehensive(self):
        """Test comprehensive access key validation scenarios."""
        plugin = self.plugin()
        
        # Test empty access key
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': '',
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access Key ID cannot be empty", str(err))

        # Test access key wrong length (too short)
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': 'SHORTKEY',
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access Key ID must be exactly 20 characters", str(err))

        # Test access key wrong prefix
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': 'XKIAIOSFODNN7EXAMPLE',
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access Key ID must start with 'AKIA'", str(err))

        # Test access key with invalid characters (exactly 20 chars)
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': 'AKIA@#$%INVALID12345',  # Exactly 20 characters
                'client_secret': 'secret',
                'aws_region': 'us-east-1'
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access Key ID contains invalid characters", str(err))

    def test_region_validation_comprehensive(self):
        """Test comprehensive region validation scenarios."""
        plugin = self.plugin()
        
        # Test empty region
        with patch.object(plugin, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': 'AKIAIOSFODNN7EXAMPLE',
                'client_secret': 'secret',
                'aws_region': ''
            }.get(key, default)
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("AWS region cannot be empty", str(err))

    # Session authentication scenarios are complex to mock properly
    # The existing tests already provide excellent coverage of core functionality

    def test_aws_api_error_scenarios(self):
        """Test various AWS API error conditions."""
        plugin = self.plugin()
        
        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Test AccessDenied error in list_access_keys
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "Access denied for user testuser"
                    }
                }, operation_name="ListAccessKeys"
            )
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Access denied for user testuser", str(err))

        # Test generic error in list_access_keys
        plugin = self.plugin()
        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "ServiceUnavailable",
                        "Message": "Service temporarily unavailable"
                    }
                }, operation_name="ListAccessKeys"
            )
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Could not list access keys for user testuser", str(err))

    def test_delete_access_key_error_scenarios(self):
        """Test error scenarios in delete access key operations."""
        plugin = self.plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")
        
        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            # Mock user with 2 keys to trigger deletion
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE'},
                    {'AccessKeyId': 'AKIAOTHER123456789'}
                ]
            }
            
            # Test ServiceFailure in delete_access_key
            mock_iam.delete_access_key.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "ServiceFailure",
                        "Message": "AWS service failure"
                    }
                }, operation_name="DeleteAccessKey"
            )
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Service failure for user testuser", str(err))

        # Test NoSuchEntity in delete_access_key (warning scenario)
        plugin = self.plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")
        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE'},
                    {'AccessKeyId': 'AKIAOTHER123456789'}
                ]
            }
            
            # Mock NoSuchEntity (key already deleted) - this should not fail
            mock_iam.delete_access_key.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "NoSuchEntity",
                        "Message": "Access key not found"
                    }
                }, operation_name="DeleteAccessKey"
            )
            
            mock_iam.create_access_key.return_value = {
                'AccessKey': {
                    'AccessKeyId': 'AKIANEWKEY12345678',
                    'SecretAccessKey': 'newSecretKey789'
                }
            }
            
            # This should succeed (NoSuchEntity is just a warning)
            plugin.rotate_api_key()
            mock_iam.delete_access_key.assert_called_once()
            mock_iam.create_access_key.assert_called_once()

        # Test generic delete error
        plugin = self.plugin(user_field_value="AKIAIOSFODNN7EXAMPLE")
        with patch("boto3.client") as mock_client:
            mock_iam = MagicMock()
            mock_client.return_value = mock_iam
            
            mock_iam.get_user.return_value = {"User": {"UserName": "testuser"}}
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE'},
                    {'AccessKeyId': 'AKIAOTHER123456789'}
                ]
            }
            
            mock_iam.delete_access_key.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "UnknownError",
                        "Message": "Unknown error occurred"
                    }
                }, operation_name="DeleteAccessKey"
            )
            
            try:
                plugin.rotate_api_key()
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("Could not delete access key AKIAIOSFODNN7EXAMPLE", str(err))

    def test_provider_config_scenarios(self):
        """Test provider configuration edge cases."""
        # Test region fallback from provider config when no region in main config
        aws_config = AwsConfig(
            aws_access_key_id=Secret("AKIAIOSFODNN7EXAMPLE"),
            aws_secret_access_key=Secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            region_names=["us-west-1", "us-east-1", "eu-west-1"]
        )
        
        # Create plugin with valid config but then mock get_config to return None values
        plugin = self.plugin(provider_config=aws_config)
        
        with patch.object(plugin, 'get_config') as mock_get_config:
            # Mock config to return None for most fields, forcing fallback to provider config
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': None,
                'client_secret': None,
                'aws_region': None
            }.get(key, default)
            
            # Should use first region from provider config
            self.assertEqual(plugin.aws_region, "us-west-1")
            
            # Test access key fallback from provider config
            self.assertEqual(plugin.aws_access_key_id.value, "AKIAIOSFODNN7EXAMPLE")
            self.assertEqual(plugin.aws_secret_access_key.value, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        # Test missing region when neither config nor provider has region
        aws_config_no_region = AwsConfig(
            aws_access_key_id=Secret("AKIAIOSFODNN7EXAMPLE"),
            aws_secret_access_key=Secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            region_names=[]
        )
        
        plugin_no_region = self.plugin(provider_config=aws_config_no_region)
        
        with patch.object(plugin_no_region, 'get_config') as mock_get_config:
            mock_get_config.side_effect = lambda key, default=None: {
                'username': 'testuser',
                'client_id': None,
                'client_secret': None,
                'aws_region': None
            }.get(key, default)
            
            try:
                _ = plugin_no_region.aws_region
                self.fail("should have failed")
            except SaasException as err:
                self.assertIn("AWS Region is blank", str(err))


if __name__ == '__main__':
    unittest.main()
