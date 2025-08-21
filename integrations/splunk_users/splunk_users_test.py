from __future__ import annotations

import importlib.util
import os
import ssl
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
        _, mock_user = self.create_mock_splunk_service(mock_client)

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
        _, mock_user = self.create_mock_splunk_service(mock_client)
        
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
        
        self.assertIn("Bad request while connecting to Splunk", str(context.exception))

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
        _, mock_user = self.create_mock_splunk_service(mock_client)
        
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

    def test_create_ssl_context_ssl_disabled_with_cert(self):
        """Test SSL context creation when SSL verification is disabled but certificate provided."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context("some cert", False)
        
        self.assertIn("Custom SSL certificate cannot be used with SSL verification disabled", str(context.exception))
        self.assertEqual("ssl_verification_required", context.exception.codes[0]["code"])

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
        host, port = SaasPlugin.validate_splunk_url("https://localhost:8089")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, 8089)

    def test_validate_splunk_url_valid_http(self):
        """Test URL validation with valid HTTP URL."""
        host, port = SaasPlugin.validate_splunk_url("http://localhost:8089")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, 8089)

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
        self.assertIn("scheme 'localhost' not supported, must be http or https", str(context.exception))

    def test_validate_splunk_url_empty_scheme(self):
        """Test URL validation with truly empty scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("://localhost:8089")
        
        self.assertIn("scheme is required", str(context.exception))

    def test_validate_splunk_url_invalid_scheme(self):
        """Test URL validation with invalid scheme."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("ftp://localhost:8089")
        
        self.assertIn("scheme 'ftp' not supported, must be http or https", str(context.exception))

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

    def test_handle_http_error_401(self):
        """Test HTTP error handling for 401 authentication failure."""
        plugin = self.plugin()
        http_error = self.create_http_error(401, "Unauthorized", "Authentication failed")
        
        with self.assertRaises(SaasException) as context:
            plugin._handle_http_error(http_error, "testing authentication")  # pylint: disable=protected-access
        
        self.assertIn("Authentication failed", str(context.exception))
        self.assertEqual("authentication_failed", context.exception.codes[0]["code"])

    def test_handle_http_error_403(self):
        """Test HTTP error handling for 403 authorization failure."""
        plugin = self.plugin()
        http_error = self.create_http_error(403, "Forbidden", "Insufficient permissions")
        
        with self.assertRaises(SaasException) as context:
            plugin._handle_http_error(http_error, "testing authorization")  # pylint: disable=protected-access
        
        self.assertIn("Authorization failed", str(context.exception))
        self.assertEqual("authorization_failed", context.exception.codes[0]["code"])

    def test_handle_http_error_404(self):
        """Test HTTP error handling for 404 not found."""
        plugin = self.plugin()
        http_error = self.create_http_error(404, "Not Found", "Resource not found")
        
        with self.assertRaises(SaasException) as context:
            plugin._handle_http_error(http_error, "testing resource access")  # pylint: disable=protected-access
        
        self.assertIn("Resource not found", str(context.exception))
        self.assertEqual("not_found", context.exception.codes[0]["code"])

    def test_handle_http_error_500(self):
        """Test HTTP error handling for 500 server error."""
        plugin = self.plugin()
        http_error = self.create_http_error(500, "Internal Server Error", "Server error")
        
        with self.assertRaises(SaasException) as context:
            plugin._handle_http_error(http_error, "testing server communication")  # pylint: disable=protected-access
        
        self.assertIn("Splunk server error", str(context.exception))
        self.assertEqual("server_error", context.exception.codes[0]["code"])

    def test_handle_http_error_other(self):
        """Test HTTP error handling for other status codes."""
        plugin = self.plugin()
        http_error = self.create_http_error(418, "I'm a teapot", "Unusual error")
        
        with self.assertRaises(SaasException) as context:
            plugin._handle_http_error(http_error, "testing unusual error")  # pylint: disable=protected-access
        
        self.assertIn("HTTP error (418)", str(context.exception))
        self.assertEqual("http_error", context.exception.codes[0]["code"])

    def test_validate_splunk_url_default_port(self):
        """Test URL validation with default port."""
        host, port = SaasPlugin.validate_splunk_url("https://localhost")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, 8089)  # DEFAULT_SPLUNK_PORT

    def test_validate_splunk_url_custom_port(self):
        """Test URL validation with custom port."""
        host, port = SaasPlugin.validate_splunk_url("https://localhost:9999")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, 9999)

    def test_validate_splunk_url_invalid_port(self):
        """Test URL validation with invalid port."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url("https://localhost:99999")
        
        self.assertIn("Port out of range 0-65535", str(context.exception))
        self.assertEqual("invalid_url_format", context.exception.codes[0]["code"])

    def test_validate_splunk_url_with_path(self):
        """Test URL validation with path (should be ignored with warning)."""
        with patch('kdnrm.log.Log.warning') as mock_warning:
            host, port = SaasPlugin.validate_splunk_url("https://localhost:8089/some/path")
            self.assertEqual(host, "localhost")
            self.assertEqual(port, 8089)
            mock_warning.assert_called()

    def test_validate_splunk_url_none(self):
        """Test URL validation with None input."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url(None)
        
        self.assertIn("Splunk URL cannot be empty", str(context.exception))

    def test_validate_splunk_url_non_string(self):
        """Test URL validation with non-string input."""
        with self.assertRaises(SaasException) as context:
            SaasPlugin.validate_splunk_url(123)
        
        self.assertIn("Splunk URL cannot be empty and must be a string", str(context.exception))

    @patch("splunk_users.client")
    def test_close_service_connection(self, mock_client):
        """Test service connection cleanup."""
        mock_service, _ = self.create_mock_splunk_service(mock_client)
        mock_service.logout = MagicMock()
        
        plugin = self.plugin()
        # Initialize service
        _ = plugin.service
        
        # Close connection
        plugin._close_service_connection()  # pylint: disable=protected-access
        
        # Verify logout was called and service was cleared
        mock_service.logout.assert_called_once()
        self.assertIsNone(plugin._service)  # pylint: disable=protected-access

    @patch("splunk_users.client")
    def test_close_service_connection_no_logout_method(self, mock_client):
        """Test service connection cleanup when logout method doesn't exist."""
        _, _ = self.create_mock_splunk_service(mock_client)
        # Don't add logout method to simulate older SDK versions
        
        plugin = self.plugin()
        # Initialize service
        _ = plugin.service
        
        # Close connection should not raise error
        plugin._close_service_connection()  # pylint: disable=protected-access
        
        # Verify service was cleared
        self.assertIsNone(plugin._service)  # pylint: disable=protected-access

    @patch("splunk_users.client")
    def test_close_service_connection_logout_exception(self, mock_client):
        """Test service connection cleanup when logout raises exception."""
        mock_service, _ = self.create_mock_splunk_service(mock_client)
        mock_service.logout = MagicMock(side_effect=Exception("Logout failed"))
        
        plugin = self.plugin()
        # Initialize service
        _ = plugin.service
        
        # Close connection should handle exception gracefully
        plugin._close_service_connection()  # pylint: disable=protected-access
        
        # Verify service was still cleared despite exception
        self.assertIsNone(plugin._service)  # pylint: disable=protected-access

    def test_create_ssl_context_ssl_disabled_no_cert(self):
        """Test SSL context creation when SSL verification is disabled and no certificate."""
        result = SaasPlugin.create_ssl_context("", False)
        self.assertIsNone(result)
        
        result = SaasPlugin.create_ssl_context(None, False)
        self.assertIsNone(result)

    def test_create_ssl_context_cert_missing_markers(self):
        """Test SSL context creation with certificate missing proper markers."""
        invalid_cert = "MIIC... some certificate data ..."
        
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(invalid_cert, True)
        
        self.assertIn("Missing '-----BEGIN CERTIFICATE-----' header", str(context.exception))
        self.assertEqual("invalid_ssl_cert_format", context.exception.codes[0]["code"])

    def test_fix_certificate_format_long_cert_data(self):
        """Test certificate format with data longer than 64 characters per line."""
        long_cert_data = "A" * 200  # Create long certificate data
        malformed_cert = f"-----BEGIN CERTIFICATE-----{long_cert_data}-----END CERTIFICATE-----"
        
        fixed_cert = SaasPlugin.fix_certificate_format(malformed_cert)
        
        # Should break lines at 64 characters
        lines = fixed_cert.split('\n')
        for line in lines[1:-1]:  # Skip header and footer
            if line:  # Skip empty lines
                self.assertLessEqual(len(line), 64)

    @patch("splunk_users.client")
    def test_verify_user_exists_general_exception(self, mock_client):
        """Test user existence verification with general exception."""
        mock_service, _ = self.create_mock_splunk_service(mock_client)
        mock_service.users.__getitem__.side_effect = Exception("General error")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._verify_user_exists()  # pylint: disable=protected-access
        
        self.assertIn("Failed to verify user existence", str(context.exception))

    @patch("splunk_users.client")
    def test_change_user_password_general_exception(self, mock_client):
        """Test password change with general exception."""
        _, mock_user = self.create_mock_splunk_service(mock_client)
        mock_user.update.side_effect = Exception("General error")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Failed to change password", str(context.exception))
        self.assertTrue(plugin.can_rollback)

    @patch("splunk_users.client")
    def test_service_connection_general_exception(self, mock_client):
        """Test service connection with general exception."""
        mock_client.connect.side_effect = Exception("Connection failed")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.service
        
        self.assertIn("Failed to connect to Splunk", str(context.exception))

    def test_verify_ssl_property(self):
        """Test verify_ssl property with different config values."""
        field_values_true = {
            "Splunk Host URL": DEFAULT_SPLUNK_HOST,
            "Splunk Admin Username": DEFAULT_ADMIN_USERNAME,
            "Splunk Admin Password": DEFAULT_ADMIN_PASSWORD,
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }
        
        field_values_false = {
            "Splunk Host URL": DEFAULT_SPLUNK_HOST,
            "Splunk Admin Username": DEFAULT_ADMIN_USERNAME,
            "Splunk Admin Password": DEFAULT_ADMIN_PASSWORD,
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }
        
        plugin_true = self.plugin(field_values=field_values_true)
        plugin_false = self.plugin(field_values=field_values_false)
        
        self.assertTrue(plugin_true.verify_ssl)
        self.assertFalse(plugin_false.verify_ssl)

    @patch("ssl.create_default_context")
    def test_create_ssl_context_ssl_error(self, mock_ssl_create):
        """Test SSL context creation with SSL error."""
        mock_ssl_create.side_effect = ssl.SSLError("Invalid certificate format")
        
        valid_cert = DEFAULT_SSL_CERT
        
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(valid_cert, True)
        
        self.assertIn("Invalid SSL certificate", str(context.exception))
        self.assertEqual("invalid_ssl_cert", context.exception.codes[0]["code"])

    @patch("ssl.create_default_context")
    def test_create_ssl_context_unexpected_error(self, mock_ssl_create):
        """Test SSL context creation with unexpected error."""
        mock_ssl_create.side_effect = ValueError("Unexpected error")
        
        valid_cert = DEFAULT_SSL_CERT
        
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(valid_cert, True)
        
        self.assertIn("Failed to process SSL certificate", str(context.exception))
        self.assertEqual("ssl_cert_processing_error", context.exception.codes[0]["code"])


if __name__ == '__main__':
    unittest.main()
