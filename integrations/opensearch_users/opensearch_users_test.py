"""Test cases for OpenSearch User Password Rotation SaaS plugin."""

from __future__ import annotations

import unittest
from typing import Optional
from unittest.mock import MagicMock, patch

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import Field, SaasUser
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

from opensearch_users import SaasPlugin


class OpenSearchUserPluginTest(unittest.TestCase):
    """Test cases for the OpenSearch User plugin."""

    def setUp(self) -> None:
        """Set up test environment."""
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    def plugin(
        self,
        prior_password: Optional[Secret] = None,
        field_values: Optional[dict] = None,
        username: Optional[Secret] = Secret("test-user"),
        user_fields: Optional[list] = None
    ) -> SaasPlugin:
        """Create a plugin instance for testing."""
        if user_fields is None:
            user_fields = [
                Field(
                    type="text",
                    label="username",
                    values=["test-user"]
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
                "OpenSearch URL": "https://opensearch.example.com:9200",
                "Admin Username": "admin",
                "Admin Password": "admin-password",
                "Verify SSL": "True",
                "SSL Certificate Content": ""
            }

        config_record = MockRecord(
            custom=[
                {
                    'type': 'text',
                    'label': 'OpenSearch URL',
                    'value': [field_values.get("OpenSearch URL")]
                },
                {
                    'type': 'text',
                    'label': 'Admin Username',
                    'value': [field_values.get("Admin Username")]
                },
                {
                    'type': 'text',
                    'label': 'Admin Password',
                    'value': [field_values.get("Admin Password")]
                },
                {
                    'type': 'text',
                    'label': 'Verify SSL',
                    'value': [field_values.get("Verify SSL")]
                },
                {
                    'type': 'text',
                    'label': 'SSL Certificate Content',
                    'value': [field_values.get("SSL Certificate Content")]
                },
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self) -> None:
        """Test that the plugin requirements are correct."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertIn("opensearch-py", req_list)

    def test_config_schema(self) -> None:
        """Test that the configuration schema is correct."""
        schema = SaasPlugin.config_schema()
        self.assertEqual(5, len(schema))
        
        schema_ids = [item.id for item in schema]
        self.assertIn("opensearch_url", schema_ids)
        self.assertIn("admin_username", schema_ids)
        self.assertIn("admin_password", schema_ids)
        self.assertIn("verify_ssl", schema_ids)
        self.assertIn("ssl_content", schema_ids)
        
        # Check required fields
        required_fields = [item for item in schema if item.required]
        self.assertEqual(3, len(required_fields))

    @patch('opensearch_users.OpenSearch')
    def test_client_creation_success(self, mock_opensearch) -> None:
        """Test successful OpenSearch client creation."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        client = plugin.client
        
        # Verify client was created and connection tested
        self.assertEqual(client, mock_client_instance)
        mock_client_instance.info.assert_called_once()

    @patch('opensearch_users.ssl.create_default_context')
    @patch('opensearch_users.OpenSearch')
    def test_client_creation_with_ssl_content(self, mock_opensearch, mock_ssl_context) -> None:
        """Test OpenSearch client creation with SSL certificate content."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        mock_opensearch.return_value = mock_client_instance
        
        # Mock SSL context creation to avoid actual SSL validation
        mock_ssl_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_ssl_context_instance
        
        # Test with SSL certificate content - use valid certificate format
        field_values = {
            "OpenSearch URL": "https://opensearch.example.com:9200",
            "Admin Username": "admin",
            "Admin Password": "admin-password",
            "Verify SSL": "True",
            "SSL Certificate Content": """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTEzNTI3WhcNMjYxMjI2MTEzNTI3WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwbVDOd2GKq6OjbqKGNMVQ2TlAV2+Fh2FpxCYkLaTdkQO6lOjFkCzfKql
XW2HQpD5jFgzd6pX4qQ7YnPxBKcJr8HNf8gPYE5vOdVcBUITdZMhS1qILRhtlSV+
Y2qp+yTx5Qz6XYwpDN5FH1vH2lH9N5FHwqC7KQEH0HrRJ5qVYGxJHUgVHqPzVnIJ
U5Z/jKMTUJJ5YCDrQ+vGb4QGnN7PqjQpXgPjS6dJLhjYKGjY2U4W8d7vAG8rqhW0
5UQMWK1jGfJpCDQ+X4JQES/YqBh8OqFGF8e0bD4CaCKdJqFQ2wIDAQABo1AwTjAd
BgNVHQ4EFgQUGCKLKB4Ij4MEI1fkGqDAQ0ZBu6owHwYDVR0jBBgwFoAUGCKLKB4I
j4MEI1fkGqDAQ0ZBu6owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
Y8Z5hRLZ+Gd5Y5jzXI4i8YJe9Ye+lIHm7F6+yW5n2q9R7tHnwJJ4xYzqCpGz8YfL
qw+ELO8VJH+jQ+YHCP+e1k+4bC6vG0a8dH1cMzV4D5vGJoQ4A3hQrLZzlJ+W5+F3
-----END CERTIFICATE-----"""
        }
        
        plugin = self.plugin(field_values=field_values)
        client = plugin.client
        
        # Verify client was created
        self.assertEqual(client, mock_client_instance)
        mock_client_instance.info.assert_called_once()
        
        # Verify SSL context was created with the certificate content
        mock_ssl_context.assert_called_once()
        
        # Verify OpenSearch was called with ssl_context parameter
        call_args = mock_opensearch.call_args
        self.assertIn('ssl_context', call_args.kwargs)
        self.assertEqual(call_args.kwargs['ssl_context'], mock_ssl_context_instance)

    @patch('opensearch_users.OpenSearch')
    def test_client_creation_failure(self, mock_opensearch) -> None:
        """Test OpenSearch client creation failure."""
        # Setup mock to raise exception
        mock_opensearch.side_effect = Exception("Connection failed")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.client
        
        self.assertIn("Failed to create OpenSearch client", str(context.exception))

    def test_validate_configuration_success(self) -> None:
        """Test successful configuration validation."""
        plugin = self.plugin()
        
        # Should not raise any exceptions
        plugin._validate_configuration()

    def test_validate_configuration_invalid_url(self) -> None:
        """Test configuration validation with invalid URL."""
        field_values = {
            "OpenSearch URL": "invalid-url",
            "Admin Username": "admin",
            "Admin Password": "admin-password",
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }
        
        # URL validation happens during plugin creation by the framework
        with self.assertRaises(SaasException) as context:
            self.plugin(field_values=field_values)
        
        # The framework validates URL format during field mapping
        self.assertIn("does not appears to be a URL", str(context.exception))

    def test_validate_configuration_empty_username(self) -> None:
        """Test configuration validation with empty username."""
        field_values = {
            "OpenSearch URL": "https://opensearch.example.com:9200",
            "Admin Username": "",
            "Admin Password": "admin-password",
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }
        
        # Empty required fields are validated by the framework
        with self.assertRaises(SaasException) as context:
            self.plugin(field_values=field_values)
        
        self.assertIn("Admin Username is required", str(context.exception))

    def test_validate_configuration_empty_password(self) -> None:
        """Test configuration validation with empty password."""
        field_values = {
            "OpenSearch URL": "https://opensearch.example.com:9200",
            "Admin Username": "admin",
            "Admin Password": "",
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }
        
        # Empty required fields are validated by the framework
        with self.assertRaises(SaasException) as context:
            self.plugin(field_values=field_values)
        
        self.assertIn("Admin Password is required", str(context.exception))



    def test_validate_opensearch_url_valid_https(self) -> None:
        """Test URL validation with valid HTTPS URL."""
        valid_url = "https://opensearch.example.com:9200"
        parsed = SaasPlugin.validate_opensearch_url(valid_url)
        
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "opensearch.example.com")
        self.assertEqual(parsed.port, 9200)

    def test_validate_opensearch_url_valid_http(self) -> None:
        """Test URL validation with valid HTTP URL."""
        valid_url = "http://localhost:9200"
        parsed = SaasPlugin.validate_opensearch_url(valid_url)
        
        self.assertEqual(parsed.scheme, "http")
        self.assertEqual(parsed.hostname, "localhost")
        self.assertEqual(parsed.port, 9200)

    def test_validate_opensearch_url_no_port(self) -> None:
        """Test URL validation with URL without explicit port."""
        valid_url = "https://opensearch.example.com"
        parsed = SaasPlugin.validate_opensearch_url(valid_url)
        
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "opensearch.example.com")
        self.assertIsNone(parsed.port)

    def test_validate_opensearch_url_empty(self) -> None:
        """Test URL validation with empty URL."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("")
        
        self.assertIn("OpenSearch URL cannot be empty", str(context.exception))

    def test_validate_opensearch_url_whitespace_only(self) -> None:
        """Test URL validation with whitespace-only URL."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("   ")
        
        self.assertIn("OpenSearch URL cannot be empty", str(context.exception))

    def test_validate_opensearch_url_no_scheme(self) -> None:
        """Test URL validation with missing scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("opensearch.example.com:9200")
        
        self.assertIn("scheme must be http or https", str(context.exception))
        self.assertIn("OpenSearch", str(context.exception))

    def test_validate_opensearch_url_empty_scheme(self) -> None:
        """Test URL validation with empty scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("://opensearch.example.com:9200")
        
        self.assertIn("scheme is required (http or https)", str(context.exception))
        self.assertIn("OpenSearch", str(context.exception))

    def test_validate_opensearch_url_invalid_scheme(self) -> None:
        """Test URL validation with invalid scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("ftp://opensearch.example.com:9200")
        
        self.assertIn("scheme must be http or https", str(context.exception))
        self.assertIn("OpenSearch", str(context.exception))

    def test_validate_opensearch_url_no_hostname(self) -> None:
        """Test URL validation with missing hostname."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("https://")
        
        self.assertIn("hostname is required", str(context.exception))
        self.assertIn("OpenSearch", str(context.exception))

    def test_validate_opensearch_url_strips_whitespace(self) -> None:
        """Test URL validation strips leading/trailing whitespace."""
        url_with_whitespace = "  https://opensearch.example.com:9200  "
        parsed = SaasPlugin.validate_opensearch_url(url_with_whitespace)
        
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "opensearch.example.com")
        self.assertEqual(parsed.port, 9200)

    def test_validate_opensearch_url_malformed(self) -> None:
        """Test URL validation with malformed URL."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_opensearch_url("not-a-url-at-all")
        
        self.assertIn("scheme is required (http or https)", str(context.exception))

    @patch('opensearch_users.OpenSearch')
    def test_is_user_present_success(self, mock_opensearch) -> None:
        """Test successful user details retrieval."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        mock_client_instance.transport.perform_request.return_value = {
            "test-user": {
                "backend_roles": ["role1"],
                "attributes": {"email": "test@example.com"}
            }
        }
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        result = plugin._is_user_present("test-user")
        
        # _is_user_present now returns True if user exists, False otherwise
        self.assertTrue(result)

    @patch('opensearch_users.OpenSearch')
    def test_is_user_present_not_found(self, mock_opensearch) -> None:
        """Test user details retrieval for non-existent user."""
        from opensearchpy.exceptions import NotFoundError
        
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        mock_client_instance.transport.perform_request.side_effect = NotFoundError(404, "not_found", {})
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._is_user_present("non-existent-user")
        
        self.assertIn("User 'non-existent-user' not found", str(context.exception))

    @patch('opensearch_users.OpenSearch')
    def test_update_user_password_success(self, mock_opensearch) -> None:
        """Test successful user password update."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        
        # Mock get user details call
        mock_client_instance.transport.perform_request.side_effect = [
            {
                "test-user": {
                    "backend_roles": ["role1"],
                    "attributes": {"email": "test@example.com"}
                }
            },
            {"status": "OK"}  # Update response
        ]
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        plugin._update_user_password("test-user", "new-password")
        
        # Verify both GET and PUT calls were made
        self.assertEqual(mock_client_instance.transport.perform_request.call_count, 2)

    @patch('opensearch_users.OpenSearch')
    def test_update_user_password_failure(self, mock_opensearch) -> None:
        """Test user password update failure."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        
        # Mock get user details success, update failure
        mock_client_instance.transport.perform_request.side_effect = [
            {
                "test-user": {
                    "backend_roles": ["role1"],
                    "attributes": {"email": "test@example.com"}
                }
            },
            {"status": "ERROR", "message": "Update failed"}  # Update response
        ]
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._update_user_password("test-user", "new-password")
        
        self.assertIn("Password update failed", str(context.exception))

    @patch('opensearch_users.OpenSearch')
    def test_update_user_password_request_error(self, mock_opensearch) -> None:
        """Test user password update with RequestError."""
        from opensearchpy.exceptions import RequestError
        
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        
        # Mock get user details success, then RequestError on update
        mock_client_instance.transport.perform_request.side_effect = [
            {
                "test-user": {
                    "backend_roles": ["role1"],
                    "attributes": {"email": "test@example.com"}
                }
            },
            RequestError(400, "request_error", {"error": "Bad request"})
        ]
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._update_user_password("test-user", "new-password")
        
        self.assertIn("Request failed", str(context.exception))

    @patch('opensearch_users.OpenSearch')
    def test_change_password_success(self, mock_opensearch) -> None:
        """Test successful password rotation."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        
        # Mock get user details and update calls
        mock_client_instance.transport.perform_request.side_effect = [
            {
                "test-user": {
                    "backend_roles": ["role1"],
                    "attributes": {"email": "test@example.com"}
                }
            },
            {"status": "OK"}  # Update response
        ]
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin()
        plugin.change_password()
        
        # Verify the password change process completed without exceptions
        # No return fields are set in the updated implementation
        self.assertEqual(0, len(plugin.return_fields))

    @patch('opensearch_users.OpenSearch')
    def test_change_password_missing_username(self, mock_opensearch) -> None:
        """Test failure when username is empty."""
        # Setup mocks to bypass client creation
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        mock_opensearch.return_value = mock_client_instance
        
        # Create user with empty string username
        user = SaasUser(
            username=Secret(""),  # Empty username
            new_password=Secret("NewPassword123"),
            prior_password=None,
            fields=[]
        )
        
        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'OpenSearch URL', 'value': ["https://opensearch.example.com:9200"]},
                {'type': 'text', 'label': 'Admin Username', 'value': ["admin"]},
                {'type': 'text', 'label': 'Admin Password', 'value': ["admin-password"]},
                {'type': 'text', 'label': 'Verify SSL', 'value': ["True"]},
                {'type': 'text', 'label': 'SSL Certificate Content', 'value': [""]},
            ]
        )
        
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        # Should now properly catch empty username
        self.assertIn("Username field is required but not found", str(context.exception))

    @patch('opensearch_users.OpenSearch')
    def test_change_password_missing_new_password(self, mock_opensearch) -> None:
        """Test failure when new password is missing."""
        # Setup mocks to bypass client creation
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        mock_opensearch.return_value = mock_client_instance
        
        # Create user with None new_password
        user = SaasUser(
            username=Secret("test-user"),
            new_password=None,
            prior_password=None,
            fields=[]
        )
        
        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'OpenSearch URL', 'value': ["https://opensearch.example.com:9200"]},
                {'type': 'text', 'label': 'Admin Username', 'value': ["admin"]},
                {'type': 'text', 'label': 'Admin Password', 'value': ["admin-password"]},
                {'type': 'text', 'label': 'Verify SSL', 'value': ["True"]},
                {'type': 'text', 'label': 'SSL Certificate Content', 'value': [""]},
            ]
        )
        
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("New password is required", str(context.exception))

    @patch('opensearch_users.OpenSearch')
    def test_change_password_client_creation_failure(self, mock_opensearch) -> None:
        """Test that change_password fails when client creation fails."""
        # Setup mock to fail on client creation
        mock_opensearch.side_effect = Exception("Failed to connect")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Failed to create OpenSearch client", str(context.exception))

    def test_change_password_validation_failure(self) -> None:
        """Test that change_password fails early on configuration validation."""
        # Create plugin with invalid configuration - invalid URL will be caught during plugin creation
        field_values = {
            "OpenSearch URL": "invalid-url",
            "Admin Username": "admin",
            "Admin Password": "admin-password",
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }
        
        # URL validation happens during plugin creation by the framework
        with self.assertRaises(SaasException) as context:
            self.plugin(field_values=field_values)
        
        # Should fail on URL validation by the framework
        self.assertIn("does not appears to be a URL", str(context.exception))

    def test_can_rollback(self) -> None:
        """Test that can_rollback returns False."""
        plugin = self.plugin()
        self.assertFalse(plugin.can_rollback)

    @patch('opensearch_users.OpenSearch')
    def test_rollback_password_success(self, mock_opensearch) -> None:
        """Test successful password rollback."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {"cluster_name": "test-cluster"}
        
        # Mock get user details and update calls for rollback
        mock_client_instance.transport.perform_request.side_effect = [
            {
                "test-user": {
                    "backend_roles": ["role1"],
                    "attributes": {"email": "test@example.com"}
                }
            },
            {"status": "OK"}  # Update response
        ]
        mock_opensearch.return_value = mock_client_instance
        
        plugin = self.plugin(prior_password=Secret("OldPassword123"))
        plugin.rollback_password()
        
        # Verify the rollback completed without exceptions
        self.assertEqual(mock_client_instance.transport.perform_request.call_count, 2)

    def test_rollback_password_no_prior_password(self) -> None:
        """Test that rollback fails when no prior password is available."""
        plugin = self.plugin(prior_password=None)
        
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("Prior password is required for rollback", str(context.exception))

    def test_ssl_certificate_format_fixing(self) -> None:
        """Test that SSL certificate format is properly fixed."""
        # Test certificate with missing line breaks - use shorter, valid cert data
        malformed_cert = "-----BEGIN CERTIFICATE----- MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTEzNTI3WhcNMjYxMjI2MTEzNTI3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbVDOd2GKq6OjbqKGNMVQ2TlAV2+Fh2FpxCYkLaTdkQO6lOjFkCzfKqlXW2HQpD5jFgzd6pX4qQ7YnPxBKcJr8HNf8gPYE5vOdVcBUITdZMhS1qILRhtlSV+Y2qp+yTx5Qz6XYwpDN5FH1vH2lH9N5FHwqC7KQEH0HrRJ5qVYGxJHUgVHqPzVnIJU5Z/jKMTUJJ5YCDrQ+vGb4QGnN7PqjQpXgPjS6dJLhjYKGjY2U4W8d7vAG8rqhW05UQMWK1jGfJpCDQ+X4JQES/YqBh8OqFGF8e0bD4CaCKdJqFQ2wIDAQABo1AwTjAdBgNVHQ4EFgQUGCKLKB4Ij4MEI1fkGqDAQ0ZBu6owHwYDVR0jBBgwFoAUGCKLKB4Ij4MEI1fkGqDAQ0ZBu6owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAY8Z5hRLZ+Gd5Y5jzXI4i8YJe9Ye+lIHm7F6+yW5n2q9R7tHnwJJ4xYzqCpGz8YfLqw+ELO8VJH+jQ+YHCP+e1k+4bC6vG0a8dH1cMzV4D5vGJoQ4A3hQrLZzlJ+W5+F3 -----END CERTIFICATE-----"
        
        fixed_cert = SaasPlugin.fix_certificate_format(malformed_cert)
        
        # Should start with proper header and newline
        self.assertTrue(fixed_cert.startswith("-----BEGIN CERTIFICATE-----\n"))
        # Should end with proper footer
        self.assertTrue(fixed_cert.endswith("\n-----END CERTIFICATE-----"))
        # Should have multiple lines
        self.assertTrue(len(fixed_cert.split('\n')) > 3)

    def test_ssl_certificate_format_already_correct(self) -> None:
        """Test that correctly formatted certificate is not modified."""
        correct_cert = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTEzNTI3WhcNMjYxMjI2MTEzNTI3WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwbVDOd2GKq6OjbqKGNMVQ2TlAV2+Fh2FpxCYkLaTdkQO6lOjFkCzfKql
XW2HQpD5jFgzd6pX4qQ7YnPxBKcJr8HNf8gPYE5vOdVcBUITdZMhS1qILRhtlSV+
Y2qp+yTx5Qz6XYwpDN5FH1vH2lH9N5FHwqC7KQEH0HrRJ5qVYGxJHUgVHqPzVnIJ
U5Z/jKMTUJJ5YCDrQ+vGb4QGnN7PqjQpXgPjS6dJLhjYKGjY2U4W8d7vAG8rqhW0
5UQMWK1jGfJpCDQ+X4JQES/YqBh8OqFGF8e0bD4CaCKdJqFQ2wIDAQABo1AwTjAd
BgNVHQ4EFgQUGCKLKB4Ij4MEI1fkGqDAQ0ZBu6owHwYDVR0jBBgwFoAUGCKLKB4I
j4MEI1fkGqDAQ0ZBu6owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
Y8Z5hRLZ+Gd5Y5jzXI4i8YJe9Ye+lIHm7F6+yW5n2q9R7tHnwJJ4xYzqCpGz8YfL
qw+ELO8VJH+jQ+YHCP+e1k+4bC6vG0a8dH1cMzV4D5vGJoQ4A3hQrLZzlJ+W5+F3
-----END CERTIFICATE-----"""
        
        result = SaasPlugin.fix_certificate_format(correct_cert)
        
        # Should return original since it's already properly formatted
        self.assertEqual(correct_cert, result)

    def test_ssl_certificate_invalid_format(self) -> None:
        """Test handling of invalid certificate format."""
        invalid_cert = "this is not a certificate"
        
        result = SaasPlugin.fix_certificate_format(invalid_cert)
        
        # Should return original content if no valid markers found
        self.assertEqual(invalid_cert, result)

    @patch('opensearch_users.ssl.create_default_context')
    def test_ssl_context_creation_with_malformed_cert(self, mock_ssl_context) -> None:
        """Test SSL context creation with malformed certificate that gets auto-fixed."""
        # Mock SSL context creation to return a valid context
        mock_ssl_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_ssl_context_instance
        
        # Test with malformed cert (missing line breaks)
        malformed_cert = "-----BEGIN CERTIFICATE----- MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTEzNTI3WhcNMjYxMjI2MTEzNTI3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbVDOd2GKq6OjbqKGNMVQ2TlAV2+Fh2FpxCYkLaTdkQO6lOjFkCzfKqlXW2HQpD5jFgzd6pX4qQ7YnPxBKcJr8HNf8gPYE5vOdVcBUITdZMhS1qILRhtlSV+Y2qp+yTx5Qz6XYwpDN5FH1vH2lH9N5FHwqC7KQEH0HrRJ5qVYGxJHUgVHqPzVnIJU5Z/jKMTUJJ5YCDrQ+vGb4QGnN7PqjQpXgPjS6dJLhjYKGjY2U4W8d7vAG8rqhW05UQMWK1jGfJpCDQ+X4JQES/YqBh8OqFGF8e0bD4CaCKdJqFQ2wIDAQABo1AwTjAdBgNVHQ4EFgQUGCKLKB4Ij4MEI1fkGqDAQ0ZBu6owHwYDVR0jBBgwFoAUGCKLKB4Ij4MEI1fkGqDAQ0ZBu6owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAY8Z5hRLZ+Gd5Y5jzXI4i8YJe9Ye+lIHm7F6+yW5n2q9R7tHnwJJ4xYzqCpGz8YfLqw+ELO8VJH+jQ+YHCP+e1k+4bC6vG0a8dH1cMzV4D5vGJoQ4A3hQrLZzlJ+W5+F3 -----END CERTIFICATE-----"
        
        # This should not raise an exception and should auto-fix the format
        result = SaasPlugin.create_ssl_context(malformed_cert, True)
        
        # Should successfully create SSL context
        self.assertEqual(result, mock_ssl_context_instance)
        
        # Verify SSL context was called with properly formatted certificate
        mock_ssl_context.assert_called_once()
        called_cert = mock_ssl_context.call_args.kwargs['cadata']
        
        # Verify the certificate was properly formatted with line breaks
        self.assertTrue(called_cert.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(called_cert.endswith("\n-----END CERTIFICATE-----"))
        self.assertTrue(len(called_cert.split('\n')) > 3)

    def test_ssl_context_creation_invalid_cert(self) -> None:
        """Test SSL context creation with invalid certificate content."""
        invalid_cert = "not a certificate"
        
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(invalid_cert, True)
        
        self.assertIn("Invalid SSL certificate format", str(context.exception))

    def test_ssl_context_creation_disabled(self) -> None:
        """Test SSL context creation when SSL verification is disabled."""
        cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        
        result = SaasPlugin.create_ssl_context(cert, False)
        
        # Should return None when SSL verification is disabled
        self.assertIsNone(result)

    def test_ssl_context_creation_no_cert(self) -> None:
        """Test SSL context creation with no certificate content."""
        result = SaasPlugin.create_ssl_context(None, True)
        self.assertIsNone(result)
        
        result = SaasPlugin.create_ssl_context("", True)
        self.assertIsNone(result)
        
        result = SaasPlugin.create_ssl_context("   ", True)
        self.assertIsNone(result)

    @patch('opensearch_users.ssl.create_default_context')
    def test_ssl_certificate_various_malformed_formats(self, mock_ssl_context) -> None:
        """Test that various malformed certificate formats are properly normalized."""
        # Mock SSL context creation to return a valid context
        mock_ssl_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_ssl_context_instance
        
        # Test case 1: Certificate with extra spaces around content
        cert_with_spaces = "  -----BEGIN CERTIFICATE-----  MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRl  -----END CERTIFICATE-----  "
        
        result = SaasPlugin.create_ssl_context(cert_with_spaces, True)
        self.assertIsNotNone(result)
        
        # Verify that ssl.create_default_context was called with normalized certificate
        mock_ssl_context.assert_called()
        call_args = mock_ssl_context.call_args[1]['cadata']
        self.assertTrue(call_args.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(call_args.endswith("\n-----END CERTIFICATE-----"))
        
        # Test case 2: Certificate with mixed line endings (CR+LF)
        mock_ssl_context.reset_mock()
        cert_with_crlf = "-----BEGIN CERTIFICATE-----\r\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEU\r\n-----END CERTIFICATE-----\r\n"
        
        result = SaasPlugin.create_ssl_context(cert_with_crlf, True)
        self.assertIsNotNone(result)
        mock_ssl_context.assert_called()
        
        # Test case 3: Certificate on single line with no line breaks
        mock_ssl_context.reset_mock()
        cert_single_line = "-----BEGIN CERTIFICATE-----MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRl-----END CERTIFICATE-----"
        
        result = SaasPlugin.create_ssl_context(cert_single_line, True)
        self.assertIsNotNone(result)
        
        # Verify proper 64-character line wrapping was applied
        call_args = mock_ssl_context.call_args[1]['cadata']
        lines = call_args.split('\n')
        # Check that certificate data lines (excluding headers/footers) are properly wrapped
        for line in lines[1:-1]:  # Skip header and footer lines
            if line.strip():  # Skip empty lines
                self.assertLessEqual(len(line), 64, f"Line too long: {line}")
        
        # Test case 4: Certificate with irregular spacing in header/footer
        mock_ssl_context.reset_mock()
        cert_irregular_spacing = "-----BEGIN   CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEU\n-----END   CERTIFICATE-----"
        
        # This should fail since the headers don't match exactly
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(cert_irregular_spacing, True)
        self.assertIn("Invalid SSL certificate format", str(context.exception))

    @patch('opensearch_users.ssl.create_default_context')
    def test_ssl_certificate_normalization_edge_cases(self, mock_ssl_context) -> None:
        """Test edge cases for certificate normalization."""
        # Mock SSL context creation to return a valid context
        mock_ssl_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_ssl_context_instance
        
        # Test case 1: Certificate with very long base64 lines (>64 chars)
        long_line_cert = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTEzNTI3WhcNMjYxMjI2MTEzNTI3WjBGMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbVDOd2GKq6OjbqKGNMVQ2TlAV2Fh2FpxCYkLaTdkQO6lOjFkCzfKqlXW2HQpD5jFgzd6pX4qQ7YnPxBKcJr8HNf8gPYE5vOdVcBUITdZMhS1qILRhtlSVY2qpyTx5Qz6XYwpDN5FH1vH2lH9N5FHwqC7KQEH0HrRJ5qVYGxJHUgVHqPzVnIJU5ZjKMTUJJ5YCDrQvGb4QGnN7PqjQpXgPjS6dJLhjYKGjY2U4W8d7vAG8rqhW05UQMWK1jGfJpCDQX4JQES
-----END CERTIFICATE-----"""
        
        result = SaasPlugin.create_ssl_context(long_line_cert, True)
        self.assertIsNotNone(result)
        
        # Verify proper line wrapping was applied
        call_args = mock_ssl_context.call_args[1]['cadata']
        lines = call_args.split('\n')
        for line in lines[1:-1]:  # Skip header and footer lines
            if line.strip():  # Skip empty lines
                self.assertLessEqual(len(line), 64, f"Line too long after normalization: {line}")
        
        # Test case 2: Certificate with tabs and multiple spaces
        mock_ssl_context.reset_mock()
        cert_with_tabs = "-----BEGIN CERTIFICATE-----\t\nMIIDXTC\t CAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEU\n  \t-----END CERTIFICATE-----"
        
        result = SaasPlugin.create_ssl_context(cert_with_tabs, True)
        self.assertIsNotNone(result)
        
        # Verify normalization removed tabs and extra spaces
        call_args = mock_ssl_context.call_args[1]['cadata']
        self.assertNotIn('\t', call_args)
        # Should not have multiple consecutive spaces in certificate data
        cert_lines = call_args.split('\n')[1:-1]  # Skip header/footer
        for line in cert_lines:
            if line.strip():
                self.assertNotIn('  ', line, f"Multiple spaces found in normalized cert line: {line}")


if __name__ == '__main__':
    unittest.main()