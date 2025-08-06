"""Test cases for Azure Application Credential SaaS plugin."""

from __future__ import annotations

import asyncio
import unittest
import uuid
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import Field, SaasUser
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

from azure_application_credential import SaasPlugin


class AzureApplicationCredentialPluginTest(unittest.TestCase):
    """Test cases for the Azure Application Credential plugin."""

    def setUp(self) -> None:
        """Set up test environment."""
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    def plugin(
        self,
        prior_password: Optional[Secret] = None,
        field_values: Optional[dict] = None,
        username: Optional[Secret] = None,
        user_fields: Optional[list] = None
    ) -> SaasPlugin:
        """Create a plugin instance for testing."""
        if username is None:
            username = Secret("test-app")
        if user_fields is None:
            user_fields = [
                Field(
                    type="text",
                    label="key_uid",
                    values=["f0b0b335-1d71-4883-8f98-567911bfdca6"]
                ),
                Field(
                    type="text",
                    label="display_name",
                    values=["Test Application Secret"]
                )
            ]

        user = SaasUser(
            username=username,
            new_password=Secret("NewPassword123"),
            prior_password=prior_password,
            fields=user_fields
        )

        if field_values is None:
            field_values = {
                "Tenant ID": "12345678-1234-1234-1234-123456789012",
                "Client ID": "87654321-4321-4321-4321-210987654321",
                "Client Secret": "test-client-secret-value",
                "Object ID": "11111111-2222-3333-4444-555555555555"
            }

        config_record = MockRecord(
            custom=[
                {
                    'type': 'text',
                    'label': 'Tenant ID',
                    'value': [field_values.get("Tenant ID")]
                },
                {
                    'type': 'text',
                    'label': 'Client ID',
                    'value': [field_values.get("Client ID")]
                },
                {
                    'type': 'text',
                    'label': 'Client Secret',
                    'value': [field_values.get("Client Secret")]
                },
                {
                    'type': 'text',
                    'label': 'Object ID',
                    'value': [field_values.get("Object ID")]
                },
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self) -> None:
        """Test that the plugin requirements are correct."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(2, len(req_list))
        self.assertIn("azure-identity", req_list)
        self.assertIn("msgraph-sdk", req_list)

    def test_config_schema(self) -> None:
        """Test that the configuration schema is correct."""
        schema = SaasPlugin.config_schema()
        self.assertEqual(4, len(schema))
        
        schema_ids = [item.id for item in schema]
        self.assertIn("tenant_id", schema_ids)
        self.assertIn("client_id", schema_ids)
        self.assertIn("client_secret", schema_ids)
        self.assertIn("object_id", schema_ids)
        
        # Check all are required and secret
        for item in schema:
            self.assertTrue(item.required)
            self.assertTrue(item.is_secret)

    @patch('azure_application_credential.asyncio.run')
    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_change_password_success(
        self, mock_graph_client, mock_credential, mock_asyncio_run
    ) -> None:
        """Test successful password rotation."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Mock the result from the combined async operation
        mock_result = MagicMock()
        mock_result.display_name = "Test Application Secret"
        mock_result.key_id = uuid.UUID("f0b0b335-1d71-4883-8f98-567911bfdca6")
        mock_result.secret_text = "new-generated-secret-value"
        
        # Mock asyncio.run to return the result (single call for _rotate_secret_async)
        mock_asyncio_run.return_value = mock_result
        
        plugin = self.plugin()
        plugin.change_password()
        
        # Verify asyncio.run was called once (for the combined operation)
        self.assertEqual(mock_asyncio_run.call_count, 1)
        
        # Verify return fields were set
        self.assertEqual(3, len(plugin.return_fields))
        
        # Check the return field labels
        return_field_labels = [field.label for field in plugin.return_fields]
        self.assertIn("display_name", return_field_labels)
        self.assertIn("key_uid", return_field_labels)
        self.assertIn("client_secret", return_field_labels)

    @patch('azure_application_credential.asyncio.run')
    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_change_password_fail_remove_error(
        self, mock_graph_client, mock_credential, mock_asyncio_run
    ) -> None:
        """Test failure during remove password operation."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Mock asyncio.run to fail (simulating delete failure in _rotate_secret_async)
        mock_asyncio_run.side_effect = SaasException("Failed to delete client secret: Remove failed")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Credential rotation failed", str(context.exception))

    @patch('azure_application_credential.asyncio.run')
    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_change_password_fail_add_error(
        self, mock_graph_client, mock_credential, mock_asyncio_run
    ) -> None:
        """Test failure during add password operation."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Mock asyncio.run to fail (simulating create failure in _rotate_secret_async)
        mock_asyncio_run.side_effect = SaasException("Failed to create new client secret: Add failed")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Credential rotation failed", str(context.exception))

    def test_change_password_missing_key_uid(self) -> None:
        """Test failure when key_uid field is missing."""
        user_fields = [
            Field(
                type="text",
                label="display_name",
                values=["Test Application Secret"]
            )
        ]
        
        plugin = self.plugin(user_fields=user_fields)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Required field 'key_uid' not found", str(context.exception))

    def test_change_password_missing_display_name(self) -> None:
        """Test failure when display_name field is missing."""
        user_fields = [
            Field(
                type="text",
                label="key_uid",
                values=["f0b0b335-1d71-4883-8f98-567911bfdca6"]
            )
        ]
        
        plugin = self.plugin(user_fields=user_fields)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Required field 'display_name' not found", str(context.exception))

    def test_rollback_password_not_supported(self) -> None:
        """Test that rollback is not supported."""
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("Rollback is not supported", str(context.exception))

    def test_can_rollback(self) -> None:
        """Test that can_rollback returns False."""
        plugin = self.plugin()
        self.assertFalse(plugin.can_rollback)

    def test_get_field_value_success(self) -> None:
        """Test successful field value retrieval."""
        plugin = self.plugin()
        key_uid = plugin._get_user_fields("key_uid")
        self.assertEqual("f0b0b335-1d71-4883-8f98-567911bfdca6", key_uid)

    def test_get_field_value_not_found(self) -> None:
        """Test field value retrieval for non-existent field."""
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._get_user_fields("non_existent_field")
        
        self.assertIn(
            "Required field 'non_existent_field' not found",
            str(context.exception)
        )

    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_delete_client_secret_success(
        self, mock_graph_client, mock_credential
    ) -> None:
        """Test successful deletion of client secret."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Mock the client to succeed (use AsyncMock for async operations)
        mock_client_instance.applications.by_application_id.return_value.remove_password.post = AsyncMock(return_value=None)
        
        plugin = self.plugin()
        object_id = "11111111-2222-3333-4444-555555555555"
        
        # Test the async delete operation directly
        asyncio.run(plugin._delete_client_secret_async(object_id))
        
        # Verify the client was accessed
        self.assertIsNotNone(plugin._client)

    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_delete_client_secret_failure(
        self, mock_graph_client, mock_credential
    ) -> None:
        """Test failure during client secret deletion."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Mock the client to raise an exception (use AsyncMock for async operations)
        mock_client_instance.applications.by_application_id.return_value.remove_password.post = AsyncMock(side_effect=Exception("Delete failed"))
        
        plugin = self.plugin()
        object_id = "11111111-2222-3333-4444-555555555555"
        
        with self.assertRaises(SaasException) as context:
            asyncio.run(plugin._delete_client_secret_async(object_id))
        
        self.assertIn("Failed to delete client secret", str(context.exception))

    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_create_client_secret_success(
        self, mock_graph_client, mock_credential
    ) -> None:
        """Test successful creation of client secret."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Create mock result
        mock_result = MagicMock()
        mock_result.display_name = "Test Application Secret"
        mock_result.key_id = uuid.UUID("f0b0b335-1d71-4883-8f98-567911bfdca6")
        mock_result.secret_text = "new-generated-secret-value"
        
        # Mock the client to return the result (use AsyncMock for async operations)
        mock_client_instance.applications.by_application_id.return_value.add_password.post = AsyncMock(return_value=mock_result)
        
        plugin = self.plugin()
        object_id = "11111111-2222-3333-4444-555555555555"
        display_name = "Test Application Secret"
        
        # Test the async create operation directly
        result = asyncio.run(plugin._create_client_secret_async(object_id, display_name))
        
        # Verify the result
        self.assertEqual(result.display_name, "Test Application Secret")
        self.assertEqual(result.secret_text, "new-generated-secret-value")

    @patch('azure_application_credential.ClientSecretCredential')
    @patch('azure_application_credential.GraphServiceClient')
    def test_create_client_secret_failure(
        self, mock_graph_client, mock_credential
    ) -> None:
        """Test failure during client secret creation."""
        # Setup mocks
        mock_credential_instance = MagicMock()
        mock_credential.return_value = mock_credential_instance
        
        mock_client_instance = MagicMock()
        mock_graph_client.return_value = mock_client_instance
        
        # Mock the client to raise an exception (use AsyncMock for async operations)
        mock_client_instance.applications.by_application_id.return_value.add_password.post = AsyncMock(side_effect=Exception("Create failed"))
        
        plugin = self.plugin()
        object_id = "11111111-2222-3333-4444-555555555555"
        display_name = "Test Application Secret"
        
        with self.assertRaises(SaasException) as context:
            asyncio.run(plugin._create_client_secret_async(object_id, display_name))
        
        self.assertIn("Failed to create new client secret", str(context.exception))


if __name__ == '__main__':
    unittest.main()