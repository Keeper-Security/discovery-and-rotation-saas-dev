from __future__ import annotations

# pylint: disable=protected-access

import importlib.util
import os
import sys
import unittest
from typing import Optional
from unittest.mock import Mock, patch

import jwt
import requests

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, ReturnCustomField
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from splunk_authentication_token import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    spec = importlib.util.spec_from_file_location(
        "splunk_authentication_token",
        os.path.join(os.path.dirname(__file__), "splunk_authentication_token.py")
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
DEFAULT_AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UiLCJqdGkiOiJ0ZXN0X3Rva2VuX2lkIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE2MDAwMDM2MDB9.test_signature"
DEFAULT_USERNAME = "testuser"
DEFAULT_NEW_TOKEN = "new_test_token_12345"


class SplunkTokenTestBase(unittest.TestCase):
    """Base class for Splunk token plugin tests."""

    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")

    def create_user(
        self, 
        username: str = DEFAULT_USERNAME,
        auth_token: str = DEFAULT_AUTH_TOKEN,
        fields: Optional[list] = None
    ):
        """Create a test user with the given parameters."""
        if fields is None:
            fields = [
                {
                    'type': 'secret',
                    'label': 'auth_token',
                    'values': [auth_token]
                }
            ]
        
        return SaasUser(
            username=Secret(username),
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

    def create_mock_response(self, status_code: int, json_data: dict = None, text: str = ""):
        """Create a mock HTTP response."""
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_data or {}
        mock_response.text = text
        mock_response.raise_for_status = Mock()
        if status_code >= 400:
            mock_response.raise_for_status.side_effect = requests.HTTPError()
        return mock_response


class SplunkTokenTestUtils:
    """Utility methods for creating test data specific to the Token plugin."""

    @staticmethod
    def create_token_config_fields(
        splunk_host: str = DEFAULT_SPLUNK_HOST,
        auth_token: str = DEFAULT_AUTH_TOKEN,
        verify_ssl: str = "False",
        ssl_content: str = ""
    ) -> list:
        """Create config fields for the Token plugin."""
        return [
            {'type': 'url', 'label': 'Splunk Host URL', 'value': [splunk_host]},
            {'type': 'secret', 'label': 'Bearer Token', 'value': [auth_token]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]


class SplunkTokenPluginTest(SplunkTokenTestBase):

    def plugin(
        self,
        field_values: Optional[dict] = None,
        user_token: Optional[str] = None
    ):
        """Create a plugin instance for testing."""
        if field_values is None:
            field_values = {
                "Splunk Host URL": DEFAULT_SPLUNK_HOST,
                "Bearer Token": DEFAULT_AUTH_TOKEN,
                "Verify SSL": "False",
                "SSL Certificate Content": ""
            }

        user = self.create_user(
            auth_token=user_token or DEFAULT_AUTH_TOKEN
        )

        config_fields = SplunkTokenTestUtils.create_token_config_fields(
            splunk_host=field_values.get("Splunk Host URL", DEFAULT_SPLUNK_HOST),
            auth_token=field_values.get("Bearer Token", DEFAULT_AUTH_TOKEN),
            verify_ssl=field_values.get("Verify SSL", "False"),
            ssl_content=field_values.get("SSL Certificate Content", "")
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(2, len(req_list))
        self.assertIn("requests", req_list)
        self.assertIn("PyJWT", req_list)

    def test_config_schema(self):
        """Test config schema contains all required fields."""
        schema = SaasPlugin.config_schema()
        self.assertEqual(4, len(schema))
        
        # Check required fields are present
        field_ids = [field.id for field in schema]
        expected_fields = [
            "splunk_host", "auth_token", "verify_ssl", "ssl_content"
        ]
        for field_id in expected_fields:
            self.assertIn(field_id, field_ids)

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

    def test_create_ssl_verification_no_cert_content(self):
        """Test SSL verification creation with no certificate content."""
        plugin = self.plugin()
        result_ssl, result_file = plugin.create_ssl_verification("", True)
        
        self.assertTrue(result_ssl)
        self.assertIsNone(result_file)

    def test_create_ssl_verification_ssl_disabled_with_cert(self):
        """Test SSL verification creation when SSL disabled but certificate provided."""
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.create_ssl_verification("some cert", False)
        
        self.assertIn("Custom SSL certificate cannot be used with SSL verification disabled", str(context.exception))

    @patch("ssl.create_default_context")
    @patch("tempfile.NamedTemporaryFile")
    def test_create_ssl_verification_valid_cert(self, mock_temp_file, mock_ssl_create):
        """Test SSL verification creation with valid certificate."""
        # Mock temporary file
        mock_file = Mock()
        mock_file.name = "/tmp/test_cert.pem"
        mock_temp_file.return_value = mock_file
        
        # Mock SSL context creation
        mock_ssl_context = Mock()
        mock_ssl_create.return_value = mock_ssl_context
        
        plugin = self.plugin()
        result_ssl, result_file = plugin.create_ssl_verification(DEFAULT_SSL_CERT, True)
        
        self.assertTrue(result_ssl)
        self.assertEqual(result_file, "/tmp/test_cert.pem")
        mock_file.write.assert_called_once()
        mock_file.close.assert_called_once()

    def test_get_field_value_from_fields_existing_field(self):
        """Test getting field value when field exists."""
        plugin = self.plugin()
        result = plugin._get_field_value_from_fields("auth_token")
        
        self.assertEqual(result, DEFAULT_AUTH_TOKEN)

    def test_get_field_value_from_fields_non_existing_field(self):
        """Test getting field value when field doesn't exist."""
        plugin = self.plugin()
        result = plugin._get_field_value_from_fields("non_existent_field")
        
        self.assertIsNone(result)

    @patch("os.path.exists")
    @patch("os.unlink")
    def test_cleanup_temp_files(self, mock_unlink, mock_exists):
        """Test temporary file cleanup."""
        mock_exists.return_value = True
        
        plugin = self.plugin()
        plugin._cert_file = "/tmp/test_cert.pem"
        
        plugin._cleanup_temp_files()
        
        mock_exists.assert_called_once_with("/tmp/test_cert.pem")
        mock_unlink.assert_called_once_with("/tmp/test_cert.pem")
        self.assertIsNone(plugin._cert_file)

    def test_get_url(self):
        """Test URL construction."""
        plugin = self.plugin()
        result = plugin._get_url("/test/path")
        
        self.assertEqual(result, "https://localhost:8089/test/path")

    def test_get_url_with_trailing_slash(self):
        """Test URL construction with trailing slash in base URL."""
        field_values = {
            "Splunk Host URL": "https://localhost:8089/",
            "Bearer Token": DEFAULT_AUTH_TOKEN,
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }
        
        plugin = self.plugin(field_values=field_values)
        result = plugin._get_url("/test/path")
        
        self.assertEqual(result, "https://localhost:8089/test/path")

    @patch("requests.get")
    def test_make_http_request_get(self, mock_get):
        """Test HTTP GET request."""
        mock_response = self.create_mock_response(200, {"result": "success"})
        mock_get.return_value = mock_response
        
        plugin = self.plugin()
        plugin._verify_param = True
        
        result = plugin._make_http_request("GET", "https://test.com", {"Authorization": "Bearer token"})
        
        self.assertEqual(result, mock_response)
        mock_get.assert_called_once()

    @patch("requests.post")
    def test_make_http_request_post(self, mock_post):
        """Test HTTP POST request."""
        mock_response = self.create_mock_response(201, {"token": "new_token"})
        mock_post.return_value = mock_response
        
        plugin = self.plugin()
        plugin._verify_param = True
        
        result = plugin._make_http_request(
            "POST", 
            "https://test.com", 
            {"Authorization": "Bearer token"}, 
            {"data": "value"}
        )
        
        self.assertEqual(result, mock_response)
        mock_post.assert_called_once()

    @patch("requests.delete")
    def test_make_http_request_delete(self, mock_delete):
        """Test HTTP DELETE request."""
        mock_response = self.create_mock_response(200)
        mock_delete.return_value = mock_response
        
        plugin = self.plugin()
        plugin._verify_param = True
        
        result = plugin._make_http_request(
            "DELETE", 
            "https://test.com", 
            {"Authorization": "Bearer token"}, 
            {"id": "token_id"}
        )
        
        self.assertEqual(result, mock_response)
        mock_delete.assert_called_once()

    def test_make_http_request_unsupported_method(self):
        """Test HTTP request with unsupported method."""
        plugin = self.plugin()
        plugin._verify_param = True
        
        with self.assertRaises(ValueError) as context:
            plugin._make_http_request("PATCH", "https://test.com", {})
        
        self.assertIn("Unsupported HTTP method: PATCH", str(context.exception))

    def test_get_auth_headers_without_content_type(self):
        """Test authorization headers without content type."""
        plugin = self.plugin()
        headers = plugin._get_auth_headers()
        
        expected = {"Authorization": f"Bearer {DEFAULT_AUTH_TOKEN}"}
        self.assertEqual(headers, expected)

    def test_get_auth_headers_with_content_type(self):
        """Test authorization headers with content type."""
        plugin = self.plugin()
        headers = plugin._get_auth_headers("application/json")
        
        expected = {
            "Authorization": f"Bearer {DEFAULT_AUTH_TOKEN}",
            "Content-Type": "application/json"
        }
        self.assertEqual(headers, expected)

    def test_decode_jwt_token_success(self):
        """Test successful JWT token decoding."""
        plugin = self.plugin()
        
        # Create a test token
        test_payload = {"sub": "testuser", "aud": "test_audience", "jti": "test_token_id"}
        test_token = jwt.encode(test_payload, "secret", algorithm="HS256")
        
        with patch("jwt.decode", return_value=test_payload):
            result = plugin._decode_jwt_token(test_token)
            
            self.assertEqual(result, test_payload)

    def test_decode_jwt_token_failure(self):
        """Test JWT token decoding failure."""
        plugin = self.plugin()
        
        with patch("jwt.decode", side_effect=jwt.DecodeError("Invalid token")):
            with self.assertRaises(SaasException) as context:
                plugin._decode_jwt_token("invalid_token")
            
            self.assertIn("Failed to decode JWT token", str(context.exception))

    def test_handle_http_error_response_400(self):
        """Test HTTP error handling for 400 Bad Request."""
        plugin = self.plugin()
        mock_response = self.create_mock_response(400, text="Bad request")
        
        with self.assertRaises(SaasException) as context:
            plugin.handle_http_error_response(mock_response, "testing")
        
        self.assertIn("Bad Request while testing", str(context.exception))

    def test_handle_http_error_response_401(self):
        """Test HTTP error handling for 401 Unauthorized."""
        plugin = self.plugin()
        mock_response = self.create_mock_response(401, text="Unauthorized")
        
        with self.assertRaises(SaasException) as context:
            plugin.handle_http_error_response(mock_response, "testing")
        
        self.assertIn("Unauthorized access while testing", str(context.exception))

    def test_handle_http_error_response_403(self):
        """Test HTTP error handling for 403 Forbidden."""
        plugin = self.plugin()
        mock_response = self.create_mock_response(403, text="Forbidden")
        
        with self.assertRaises(SaasException) as context:
            plugin.handle_http_error_response(mock_response, "testing")
        
        self.assertIn("Forbidden: Access denied while testing", str(context.exception))

    def test_handle_http_error_response_404(self):
        """Test HTTP error handling for 404 Not Found."""
        plugin = self.plugin()
        mock_response = self.create_mock_response(404, text="Not found")
        
        with self.assertRaises(SaasException) as context:
            plugin.handle_http_error_response(mock_response, "testing")
        
        self.assertIn("Resource not found while testing", str(context.exception))

    def test_handle_http_error_response_500(self):
        """Test HTTP error handling for 500 Server Error."""
        plugin = self.plugin()
        mock_response = self.create_mock_response(500, text="Server error")
        
        with self.assertRaises(SaasException) as context:
            plugin.handle_http_error_response(mock_response, "testing")
        
        self.assertIn("Server error while testing", str(context.exception))

    @patch.object(SaasPlugin, "_make_http_request")
    def test_generate_token_success(self, mock_http_request):
        """Test successful token generation."""
        mock_response = self.create_mock_response(
            201, 
            {"entry": [{"content": {"token": DEFAULT_NEW_TOKEN}}]}
        )
        mock_http_request.return_value = mock_response
        
        plugin = self.plugin()
        result = plugin._generate_token("test_audience", "test_user")
        
        self.assertEqual(result, DEFAULT_NEW_TOKEN)
        mock_http_request.assert_called_once()

    @patch.object(SaasPlugin, "_make_http_request")
    def test_generate_token_failure(self, mock_http_request):
        """Test token generation failure."""
        mock_response = self.create_mock_response(400, text="Bad request")
        mock_http_request.return_value = mock_response
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException):
            plugin._generate_token("test_audience", "test_user")

    @patch.object(SaasPlugin, "_make_http_request")
    def test_delete_token_success(self, mock_http_request):
        """Test successful token deletion."""
        mock_response = self.create_mock_response(200)
        mock_http_request.return_value = mock_response
        
        plugin = self.plugin()
        
        # Should not raise exception
        plugin._delete_token("test_token_id", "test_user")
        
        mock_http_request.assert_called_once()

    @patch.object(SaasPlugin, "_make_http_request")
    def test_delete_token_failure(self, mock_http_request):
        """Test token deletion failure."""
        mock_response = self.create_mock_response(404, text="Not found")
        mock_http_request.return_value = mock_response
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException):
            plugin._delete_token("test_token_id", "test_user")

    @patch.object(SaasPlugin, "_make_http_request")
    def test_check_token_exists_true(self, mock_http_request):
        """Test token existence check when token exists."""
        mock_response = self.create_mock_response(200)
        mock_http_request.return_value = mock_response
        
        plugin = self.plugin()
        result = plugin._check_token_exists("test_token_id")
        
        self.assertTrue(result)
        mock_http_request.assert_called_once()

    @patch.object(SaasPlugin, "_make_http_request")
    def test_check_token_exists_false(self, mock_http_request):
        """Test token existence check when token doesn't exist."""
        mock_response = self.create_mock_response(404, text="Not found")
        mock_http_request.return_value = mock_response
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException):
            plugin._check_token_exists("test_token_id")

    @patch.object(SaasPlugin, "_make_http_request")
    def test_check_token_exists_request_exception(self, mock_http_request):
        """Test token existence check with request exception."""
        mock_http_request.side_effect = requests.RequestException("Connection error")
        
        plugin = self.plugin()
        result = plugin._check_token_exists("test_token_id")
        
        self.assertFalse(result)

    @patch.object(SaasPlugin, "_generate_token")
    @patch.object(SaasPlugin, "_delete_token")
    @patch.object(SaasPlugin, "_check_token_exists")
    @patch.object(SaasPlugin, "_decode_jwt_token")
    def test_change_password_success(self, mock_decode, mock_check, mock_delete, mock_generate):
        """Test successful token rotation."""
        # Mock JWT payload
        mock_payload = {
            "jti": "old_token_id",
            "aud": "test_audience",
            "sub": "test_user"
        }
        mock_decode.return_value = mock_payload
        mock_check.return_value = True
        mock_generate.return_value = DEFAULT_NEW_TOKEN
        
        plugin = self.plugin()
        plugin.change_password()
        
        # Verify all methods were called
        mock_decode.assert_called_once()
        mock_check.assert_called_once_with("old_token_id")
        mock_generate.assert_called_once_with("test_audience", "test_user")
        mock_delete.assert_called_once_with("old_token_id", "test_user")
        
        # Verify return field was added
        self.assertEqual(len(plugin.return_fields), 1)
        self.assertEqual(plugin.return_fields[0].label, "auth_token")

    def test_change_password_no_token(self):
        """Test token rotation when no token is provided."""
        user = self.create_user(auth_token=None, fields=[])
        config_fields = SplunkTokenTestUtils.create_token_config_fields()
        config_record = self.create_config_record(config_fields)
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("No bearer token provided for authentication", str(context.exception))

    @patch.object(SaasPlugin, "_decode_jwt_token")
    def test_change_password_invalid_jwt_claims(self, mock_decode):
        """Test token rotation with invalid JWT claims."""
        # Mock JWT payload missing required claims
        mock_payload = {"sub": "test_user"}  # Missing 'jti' and 'aud'
        mock_decode.return_value = mock_payload
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("JWT is missing required claims", str(context.exception))

    def test_rollback_password(self):
        """Test password rollback (not supported)."""
        plugin = self.plugin()
        
        # Should not raise exception
        plugin.rollback_password()

    def test_add_return_field(self):
        """Test adding return field."""
        plugin = self.plugin()
        test_field = ReturnCustomField(
            label="test_field",
            type="secret",
            value=Secret("test_value")
        )
        
        plugin.add_return_field(test_field)
        
        self.assertEqual(len(plugin.return_fields), 1)
        self.assertEqual(plugin.return_fields[0], test_field)


if __name__ == '__main__':
    unittest.main()
