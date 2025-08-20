from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from typing import Optional
from unittest.mock import MagicMock, patch
from splunklib.binding import HTTPError


from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from splunk_users import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    spec = importlib.util.spec_from_file_location(
        "splunk_users",
        os.path.join(os.path.dirname(__file__), "splunk_users.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SaasPlugin = module.SaasPlugin


# Test constants
DEFAULT_SPLUNK_HOST = "https://localhost:8089"
DEFAULT_SSL_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC...\n"
    "-----END CERTIFICATE-----"
)
DEFAULT_USERNAME = "testuser"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "AdminPassword123!"
DEFAULT_NEW_PASSWORD = "NewPassword123!"
DEFAULT_PRIOR_PASSWORD = "OldPassword123!"


class SplunkTestBase(unittest.TestCase):
    """Base class for Splunk plugin tests."""

    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")

    def create_mock_splunk_service(self, mock_client_class):
        """Create a mock Splunk service that behaves correctly."""
        mock_service = MagicMock()
        
        # Mock users collection
        mock_users = MagicMock()
        mock_service.users = mock_users
        
        # Mock user entity
        mock_user = MagicMock()
        mock_user.name = DEFAULT_USERNAME
        mock_user.update = MagicMock()
        mock_users.__getitem__.return_value = mock_user
        
        mock_client_class.connect.return_value = mock_service
        return mock_service, mock_user

    def create_user(
        self, 
        username: str, 
        new_password: str, 
        prior_password: Optional[str] = None, 
        fields: Optional[list] = None
    ):
        """Create a test user with the given parameters."""
        if fields is None:
            fields = []
        
        return SaasUser(
            username=Secret(username),
            new_password=Secret(new_password) if new_password else None,
            prior_password=Secret(prior_password) if prior_password else None,
            fields=fields
        )

    def create_config_record(self, config_fields: list):
        """Create a MockRecord with the given config fields."""
        return MockRecord(custom=config_fields)

    def create_field(
        self, 
        field_type: str, 
        label: str, 
        value: str, 
        is_secret: bool = False
    ):
        """Create a configuration field."""
        return {
            'type': 'secret' if is_secret else field_type,
            'label': label,
            'value': [value]
        }

    def create_http_error(self, status: int, reason: str, message: str = None):
        """Create a properly mocked HTTPError for testing."""
        mock_response = MagicMock()
        mock_response.status = status
        mock_response.reason = reason
        # Mock the body.read() to return valid XML bytes that HTTPError expects
        xml_message = message or reason
        mock_response.body.read.return_value = f'<response><messages><msg>{xml_message}</msg></messages></response>'.encode()
        return HTTPError(mock_response, f"HTTP {status} {reason}")


class SplunkUsersTestUtils:
    """Utility methods for creating test data specific to the Users plugin."""

    @staticmethod
    def create_users_config_fields(
        splunk_host: str = DEFAULT_SPLUNK_HOST,
        username: str = DEFAULT_ADMIN_USERNAME,
        password: str = DEFAULT_ADMIN_PASSWORD,
        verify_ssl: str = "False",
        ssl_content: str = ""
    ) -> list:
        """Create config fields for the Users plugin."""
        return [
            {'type': 'url', 'label': 'Splunk Host URL', 'value': [splunk_host]},
            {'type': 'text', 'label': 'Splunk Admin Username', 'value': [username]},
            {'type': 'secret', 'label': 'Splunk Admin Password', 'value': [password]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]


class SplunkUserPluginTest(SplunkTestBase):

    def plugin(
        self,
        prior_password: Optional[Secret] = None,
        field_values: Optional[dict] = None,
        username: Optional[Secret] = None
    ):

        if username is None:
            username = Secret(DEFAULT_USERNAME)

        user = self.create_user(
            username=username.value,
            new_password=DEFAULT_NEW_PASSWORD,
            prior_password=prior_password.value if prior_password else None
        )

        if field_values is None:
            field_values = {
                "Splunk Host URL": DEFAULT_SPLUNK_HOST,
                "Splunk Admin Username": DEFAULT_ADMIN_USERNAME,
                "Splunk Admin Password": DEFAULT_ADMIN_PASSWORD,
                "Verify SSL": "False",
                "SSL Certificate Content": ""
            }

        config_fields = SplunkUsersTestUtils.create_users_config_fields(
            splunk_host=field_values.get("Splunk Host URL", DEFAULT_SPLUNK_HOST),
            username=field_values.get("Splunk Admin Username", DEFAULT_ADMIN_USERNAME),
            password=field_values.get("Splunk Admin Password", DEFAULT_ADMIN_PASSWORD),
            verify_ssl=field_values.get("Verify SSL", "False"),
            ssl_content=field_values.get("SSL Certificate Content", "")
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual(req_list[0], "splunk-sdk")

    def test_config_schema(self):
        """Test config schema contains all required fields."""
        schema = SaasPlugin.config_schema()
        self.assertEqual(5, len(schema))
        
        # Check required fields are present
        field_ids = [field.id for field in schema]
        expected_fields = [
            "splunk_host", "username", "password", "verify_ssl", "ssl_content"
        ]
        for field_id in expected_fields:
            self.assertIn(field_id, field_ids)

    @patch("splunk_users.client")
    def test_change_password_success_https(self, mock_client):
        """Test successful password change with HTTPS connection."""
        mock_service, mock_user = self.create_mock_splunk_service(mock_client)

        plugin = self.plugin()
        plugin.change_password()

        # Verify service connection was established
        mock_client.connect.assert_called_once()
        
        # Verify user update was called with correct password
        mock_user.update.assert_called_once_with(password=DEFAULT_NEW_PASSWORD)

    @patch("splunk_users.client")
    def test_change_password_success_ssl_disabled(self, mock_client):
        """Test successful password change with SSL verification disabled."""
        field_values = {
            "Splunk Host URL": DEFAULT_SPLUNK_HOST,
            "Splunk Admin Username": DEFAULT_ADMIN_USERNAME,
            "Splunk Admin Password": DEFAULT_ADMIN_PASSWORD,
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }

        _, _ = self.create_mock_splunk_service(mock_client)

        plugin = self.plugin(field_values=field_values)
        plugin.change_password()

        # Verify connection was made with SSL verification disabled
        call_args = mock_client.connect.call_args[1]
        self.assertFalse(call_args['verify'])

    @patch("splunk_users.client")
    def test_change_password_success_with_custom_cert(self, mock_client):
        """Test successful password change with custom SSL certificate."""
        field_values = {
            "Splunk Host URL": "https://localhost:8089",
            "Splunk Admin Username": DEFAULT_ADMIN_USERNAME,
            "Splunk Admin Password": DEFAULT_ADMIN_PASSWORD,
            "Verify SSL": "True",
            "SSL Certificate Content": DEFAULT_SSL_CERT
        }

        _, _ = self.create_mock_splunk_service(mock_client)

        with patch("ssl.create_default_context") as mock_ssl:
            mock_ssl_context = MagicMock()
            mock_ssl.return_value = mock_ssl_context

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify custom SSL context was used
            call_args = mock_client.connect.call_args[1]
            self.assertTrue(call_args['verify'])
            self.assertIn('context', call_args)
            mock_ssl.assert_called_once()

    @patch("splunk_users.client")
    def test_change_password_success_ssl_enabled_no_cert(self, mock_client):
        """Test successful password change with SSL enabled but no custom certificate."""
        field_values = {
            "Splunk Host URL": "https://localhost:8089",
            "Splunk Admin Username": DEFAULT_ADMIN_USERNAME,
            "Splunk Admin Password": DEFAULT_ADMIN_PASSWORD,
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }

        _, _ = self.create_mock_splunk_service(mock_client)

        plugin = self.plugin(field_values=field_values)
        plugin.change_password()

        # Verify SSL verification was enabled but no custom context
        call_args = mock_client.connect.call_args[1]
        self.assertTrue(call_args['verify'])
        self.assertNotIn('context', call_args)

    @patch("splunk_users.client")
    def test_change_password_user_not_found(self, mock_client):
        """Test password change when user does not exist."""
        mock_service, _ = self.create_mock_splunk_service(mock_client)
        mock_service.users.__getitem__.side_effect = KeyError("User not found")

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("does not exist in Splunk", str(context.exception))

    @patch("splunk_users.client")
    def test_change_password_http_error_403(self, mock_client):
        """Test password change with 403 authorization error."""
        _, mock_user = self.create_mock_splunk_service(mock_client)
        
        # Mock HTTPError with 403 status
        http_error = self.create_http_error(403, "Forbidden")
        mock_user.update.side_effect = http_error

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Authorization failed", str(context.exception))

    @patch("splunk_users.client")
    def test_change_password_http_error_400(self, mock_client):
        """Test password change with 400 bad request error."""
        mock_service, mock_user = self.create_mock_splunk_service(mock_client)
        
        # Mock HTTPError with 400 status
        http_error = self.create_http_error(400, "Bad Request")
        mock_user.update.side_effect = http_error

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Invalid password change request", str(context.exception))
        self.assertTrue(plugin.can_rollback)

    @patch("splunk_users.client")
    def test_service_connection_auth_error_401(self, mock_client):
        """Test service connection with 401 authentication error."""
        # Mock HTTPError with 401 status for connection failure
        http_error = self.create_http_error(401, "Unauthorized")
        mock_client.connect.side_effect = http_error

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.service  # This triggers the connection
        
        self.assertIn("Authentication failed", str(context.exception))

    @patch("splunk_users.client")
    def test_service_connection_bad_request_400(self, mock_client):
        """Test service connection with 400 bad request error."""
        # Mock HTTPError with 400 status for connection failure
        http_error = self.create_http_error(400, "Bad Request")
        mock_client.connect.side_effect = http_error

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.service  # This triggers the connection
        
        self.assertIn("Bad request when connecting to Splunk", str(context.exception))

    def test_change_password_no_new_password(self):
        """Test password change when no new password is provided."""
        user = self.create_user(
            username=DEFAULT_USERNAME,
            new_password=None  # No new password
        )
        
        config_fields = SplunkUsersTestUtils.create_users_config_fields()
        config_record = self.create_config_record(config_fields)
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("No new password provided", str(context.exception))

    @patch("splunk_users.client")
    def test_rollback_password_success(self, mock_client):
        """Test successful password rollback."""
        mock_service, mock_user = self.create_mock_splunk_service(mock_client)
        
        plugin = self.plugin(prior_password=Secret(DEFAULT_PRIOR_PASSWORD))
        plugin.can_rollback = True
        
        plugin.rollback_password()
        
        # Verify user update was called with prior password
        mock_user.update.assert_called_once_with(password=DEFAULT_PRIOR_PASSWORD)

    def test_rollback_password_no_prior_password(self):
        """Test password rollback when no prior password is available."""
        plugin = self.plugin()  # No prior password
        
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("No prior password available", str(context.exception))

    def test_should_verify_ssl_true(self):
        """Test SSL verification with True value."""
        result = SaasPlugin.should_verify_ssl("True")
        self.assertTrue(result)

    def test_should_verify_ssl_false(self):
        """Test SSL verification with False value."""
        result = SaasPlugin.should_verify_ssl("False")
        self.assertFalse(result)

    def test_should_verify_ssl_other_values(self):
        """Test SSL verification with other values."""
        for value in ["true", "false", "1", "0", "yes", "no"]:
            result = SaasPlugin.should_verify_ssl(value)
            self.assertFalse(result)  # Only "True" should return True

    def test_fix_certificate_format_valid_cert(self):
        """Test certificate format fixing with valid certificate."""
        malformed_cert = (
            "-----BEGIN CERTIFICATE-----MIIC... more data here ..."
            "-----END CERTIFICATE-----"
        )
        
        fixed_cert = SaasPlugin.fix_certificate_format(malformed_cert)
        
        self.assertTrue(fixed_cert.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(fixed_cert.endswith("\n-----END CERTIFICATE-----"))

    def test_fix_certificate_format_invalid_cert(self):
        """Test certificate format fixing with invalid certificate."""
        invalid_cert = "Not a certificate"
        
        result = SaasPlugin.fix_certificate_format(invalid_cert)
        
        # Should return original if no markers found
        self.assertEqual(result, invalid_cert)

    def test_create_ssl_context_ssl_disabled(self):
        """Test SSL context creation when SSL verification is disabled."""
        result = SaasPlugin.create_ssl_context("some cert", False)
        self.assertIsNone(result)

    def test_create_ssl_context_no_cert_content(self):
        """Test SSL context creation with no certificate content."""
        result = SaasPlugin.create_ssl_context("", True)
        self.assertIsNone(result)
        
        result = SaasPlugin.create_ssl_context(None, True)
        self.assertIsNone(result)

    def test_create_ssl_context_invalid_cert(self):
        """Test SSL context creation with invalid certificate."""
        invalid_cert = "Not a valid certificate"
        
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(invalid_cert, True)
        
        self.assertIn("Invalid SSL certificate format", str(context.exception))

    @patch("ssl.create_default_context")
    def test_create_ssl_context_valid_cert(self, mock_ssl_create):
        """Test SSL context creation with valid certificate."""
        mock_ssl_context = MagicMock()
        mock_ssl_create.return_value = mock_ssl_context
        
        valid_cert = DEFAULT_SSL_CERT
        
        result = SaasPlugin.create_ssl_context(valid_cert, True)
        
        self.assertEqual(result, mock_ssl_context)
        mock_ssl_create.assert_called_once_with(cadata=valid_cert)

    def test_validate_splunk_url_valid_https(self):
        """Test URL validation with valid HTTPS URL."""
        # Should not raise exception
        SaasPlugin.validate_splunk_url("https://localhost:8089")

    def test_validate_splunk_url_valid_http(self):
        """Test URL validation with valid HTTP URL."""
        # Should not raise exception
        SaasPlugin.validate_splunk_url("http://localhost:8089")

    def test_validate_splunk_url_empty(self):
        """Test URL validation with empty URL."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("")
        
        self.assertIn("Splunk URL cannot be empty", str(context.exception))

    def test_validate_splunk_url_no_scheme(self):
        """Test URL validation with missing scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("localhost:8089")
        
        # When no scheme prefix (http://), urlparse treats "localhost" as scheme
        self.assertIn("scheme must be http or https", str(context.exception))

    def test_validate_splunk_url_empty_scheme(self):
        """Test URL validation with truly empty scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("://localhost:8089")
        
        self.assertIn("scheme is required", str(context.exception))

    def test_validate_splunk_url_invalid_scheme(self):
        """Test URL validation with invalid scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("ftp://localhost:8089")
        
        self.assertIn("scheme must be http or https", str(context.exception))

    def test_validate_splunk_url_no_hostname(self):
        """Test URL validation with missing hostname."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("https://")
        
        self.assertIn("hostname is required", str(context.exception))

    def test_ssl_certificate_normalization_edge_cases(self):
        """Test certificate normalization handles edge cases correctly."""
        # Test with tabs and extra whitespace
        cert_with_tabs = (
            "-----BEGIN CERTIFICATE-----\t\n"
            "MIIC...\t \n"
            "-----END CERTIFICATE-----\t"
        )
        
        normalized = SaasPlugin.fix_certificate_format(cert_with_tabs)
        
        # Tabs should be removed
        self.assertNotIn('\t', normalized)
        # Should have proper format
        self.assertTrue(normalized.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(normalized.endswith("\n-----END CERTIFICATE-----"))


if __name__ == '__main__':
    unittest.main()
