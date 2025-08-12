from __future__ import annotations

import importlib.util
import os
import ssl
import sys
import tempfile
import unittest
from typing import Optional
from unittest.mock import MagicMock, patch, mock_open

from requests.exceptions import RequestException, Timeout, ConnectionError

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from jfrog_users import SaasPlugin, HEALTH_ENDPOINT, API_ENDPOINT
except ImportError:
    # Alternative import if direct import fails
    spec = importlib.util.spec_from_file_location(
        "jfrog_users",
        os.path.join(os.path.dirname(__file__), "jfrog_users.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SaasPlugin = module.SaasPlugin
    HEALTH_ENDPOINT = module.HEALTH_ENDPOINT
    API_ENDPOINT = module.API_ENDPOINT

# Test constants
DEFAULT_JFROG_URL = "https://mycompany.jfrog.io"
DEFAULT_ACCESS_TOKEN = "test_access_token_12345"
DEFAULT_SSL_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC...\n"
    "-----END CERTIFICATE-----"
)
DEFAULT_USERNAME = "testuser"
DEFAULT_NEW_PASSWORD = "NewPassword123!"
DEFAULT_PRIOR_PASSWORD = "OldPassword123!"


class JFrogTestBase(unittest.TestCase):
    """Base class for JFrog plugin tests."""

    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")

    def create_mock_response(self, status_code: int, json_data: dict = None, text: str = ""):
        """Create a mock HTTP response."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_data or {}
        mock_response.text = text
        return mock_response

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


class JFrogUsersTestUtils:
    """Utility methods for creating test data specific to the JFrog Users plugin."""

    @staticmethod
    def create_jfrog_config_fields(
        jfrog_url: str = DEFAULT_JFROG_URL,
        access_token: str = DEFAULT_ACCESS_TOKEN,
        verify_ssl: str = "False",
        ssl_content: str = ""
    ) -> list:
        """Create config fields for the JFrog Users plugin."""
        return [
            {'type': 'url', 'label': 'JFrog URL', 'value': [jfrog_url]},
            {'type': 'secret', 'label': 'Admin Access Token', 'value': [access_token]},
            {'type': 'enum', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]


class JFrogUserPluginTest(JFrogTestBase):

    def plugin(
        self,
        prior_password: Optional[Secret] = None,
        field_values: Optional[dict] = None,
        username: Optional[Secret] = None
    ):
        if username is None:
            username = Secret("testuser")

        user = self.create_user(
            username=username.value,
            new_password="NewPassword123!",
            prior_password=prior_password.value if prior_password else None
        )

        if field_values is None:
            field_values = {
                "Admin Access Token": DEFAULT_ACCESS_TOKEN,
                "JFrog URL": DEFAULT_JFROG_URL,
                "Verify SSL": "True",
                "SSL Certificate Content": ""
            }

        config_fields = JFrogUsersTestUtils.create_jfrog_config_fields(
            jfrog_url=field_values.get("JFrog URL", DEFAULT_JFROG_URL),
            access_token=field_values.get("Admin Access Token", DEFAULT_ACCESS_TOKEN),
            verify_ssl=field_values.get("Verify SSL", "True"),
            ssl_content=field_values.get("SSL Certificate Content", "")
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual(req_list[0], "requests")

    @patch('jfrog_users.requests.Session')
    def test_change_password_success(self, mock_session_class):
        """Test successful password change."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock the responses
        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(204)

        mock_session.request.side_effect = [health_response, user_response, password_response]

        plugin = self.plugin()
        plugin.change_password()

        # Verify the calls
        self.assertEqual(mock_session.request.call_count, 3)
        
        # Check health check call
        health_call = mock_session.request.call_args_list[0]
        self.assertEqual(health_call[0][0], 'GET')
        self.assertIn(HEALTH_ENDPOINT, health_call[0][1])

        # Check user verification call
        user_call = mock_session.request.call_args_list[1]
        self.assertEqual(user_call[0][0], 'GET')
        self.assertIn(f'{API_ENDPOINT}/users/testuser', user_call[0][1])

        # Check password change call
        password_call = mock_session.request.call_args_list[2]
        self.assertEqual(password_call[0][0], 'PUT')
        self.assertIn(f'{API_ENDPOINT}/users/testuser/password', password_call[0][1])
        self.assertEqual(password_call[1]['json'], {"password": "NewPassword123!"})

    @patch('jfrog_users.requests.Session')
    def test_change_password_ssl_disabled(self, mock_session_class):
        """Test password change with SSL verification disabled."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        field_values = {
            "Admin Access Token": DEFAULT_ACCESS_TOKEN,
            "JFrog URL": DEFAULT_JFROG_URL,
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }

        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(204)

        mock_session.request.side_effect = [health_response, user_response, password_response]

        plugin = self.plugin(field_values=field_values)
        plugin.change_password()

        # Verify SSL verification was disabled
        self.assertFalse(mock_session.verify)

    @patch('jfrog_users.requests.Session')
    @patch('jfrog_users.tempfile.mkstemp')
    @patch('builtins.open', new_callable=mock_open)
    @patch('jfrog_users.os.fdopen')
    def test_change_password_with_custom_cert(self, mock_fdopen, mock_open_builtin, mock_mkstemp, mock_session_class):
        """Test password change with custom SSL certificate."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock temp file creation
        mock_mkstemp.return_value = (123, '/tmp/jfrog_cert_abc.crt')
        mock_file = MagicMock()
        mock_fdopen.return_value.__enter__.return_value = mock_file

        field_values = {
            "Admin Access Token": DEFAULT_ACCESS_TOKEN,
            "JFrog URL": DEFAULT_JFROG_URL,
            "Verify SSL": "True",
            "SSL Certificate Content": DEFAULT_SSL_CERT
        }

        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(204)

        mock_session.request.side_effect = [health_response, user_response, password_response]

        with patch('ssl.create_default_context') as mock_ssl:
            mock_ssl_context = MagicMock()
            mock_ssl.return_value = mock_ssl_context

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify custom certificate file was used
            self.assertEqual(mock_session.verify, '/tmp/jfrog_cert_abc.crt')
            mock_ssl.assert_called_once_with(cadata=DEFAULT_SSL_CERT.strip())

    @patch('jfrog_users.requests.Session')
    def test_change_password_user_not_found(self, mock_session_class):
        """Test password change when user doesn't exist."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(404)

        mock_session.request.side_effect = [health_response, user_response]

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("does not exist in JFrog platform", str(context.exception))

    @patch('jfrog_users.requests.Session')
    def test_change_password_authentication_failed(self, mock_session_class):
        """Test password change with authentication failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(401)

        mock_session.request.side_effect = [health_response, user_response, password_response]

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Authentication failed", str(context.exception))

    @patch('jfrog_users.requests.Session')
    def test_change_password_authorization_failed(self, mock_session_class):
        """Test password change with authorization failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(403)

        mock_session.request.side_effect = [health_response, user_response, password_response]

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Authorization failed", str(context.exception))

    @patch('jfrog_users.requests.Session')
    def test_change_password_bad_request(self, mock_session_class):
        """Test password change with bad request (400) response."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(200)
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(
            400, 
            {"error": "Password does not meet policy requirements"}, 
            "Bad Request"
        )

        mock_session.request.side_effect = [health_response, user_response, password_response]

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Invalid password change request", str(context.exception))
        self.assertIn("Password does not meet policy requirements", str(context.exception))
        self.assertTrue(plugin.can_rollback)

    @patch('jfrog_users.requests.Session')
    def test_change_password_connection_error(self, mock_session_class):
        """Test password change with connection error."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = ConnectionError("Connection failed")

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Cannot connect to JFrog platform", str(context.exception))

    @patch('jfrog_users.requests.Session')
    def test_change_password_timeout(self, mock_session_class):
        """Test password change with timeout."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Timeout("Request timeout")

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Request timeout to JFrog platform", str(context.exception))

    def test_change_password_no_new_password(self):
        """Test password change when no new password is provided."""
        user = SaasUser(
            username=Secret("testuser"),
            new_password=None,
            prior_password=None
        )

        config_record = MockRecord(
            custom=[
                {'type': 'secret', 'label': 'Admin Access Token', 'value': [DEFAULT_ACCESS_TOKEN]},
                {'type': 'url', 'label': 'JFrog URL', 'value': [DEFAULT_JFROG_URL]},
                {'type': 'enum', 'label': 'Verify SSL', 'value': ["True"]},
                {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [""]},
            ]
        )

        plugin = SaasPlugin(user=user, config_record=config_record)

        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("No new password provided", str(context.exception))

    @patch('jfrog_users.requests.Session')
    def test_rollback_success(self, mock_session_class):
        """Test successful password rollback."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Only 2 calls for rollback: user verification and password change
        user_response = self.create_mock_response(200, {"username": "testuser"})
        password_response = self.create_mock_response(204)

        mock_session.request.side_effect = [user_response, password_response]

        plugin = self.plugin(prior_password=Secret("OldPassword123!"))
        plugin.rollback_password()

        # Verify rollback was called with prior password
        password_call = mock_session.request.call_args_list[1]
        self.assertEqual(password_call[1]['json'], {"password": "OldPassword123!"})

    def test_rollback_no_prior_password(self):
        """Test rollback failure when no prior password is available."""
        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("No prior password available", str(context.exception))

    def test_can_rollback_initial_state(self):
        """Test can_rollback property returns False initially."""
        plugin = self.plugin()
        self.assertFalse(plugin.can_rollback)

    @patch('jfrog_users.requests.Session')
    def test_can_rollback_after_user_verification(self, mock_session_class):
        """Test can_rollback property returns True after successful user verification."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        user_response = self.create_mock_response(200, {"username": "testuser"})
        mock_session.request.return_value = user_response

        plugin = self.plugin()
        plugin._verify_user_exists()
        
        self.assertTrue(plugin.can_rollback)

    def test_config_schema(self):
        """Test configuration schema."""
        schema = SaasPlugin.config_schema()
        
        # Verify required fields
        field_ids = [item.id for item in schema]
        expected_fields = ["jfrog_url", "access_token", "verify_ssl", "ssl_content"]
        
        for field in expected_fields:
            self.assertIn(field, field_ids)
        
        # Verify access_token is secret
        token_field = next(item for item in schema if item.id == "access_token")
        self.assertTrue(token_field.is_secret)
        
        # Verify URL field type
        url_field = next(item for item in schema if item.id == "jfrog_url")
        self.assertEqual(url_field.type, "url")
        
        # Verify SSL enum values
        ssl_field = next(item for item in schema if item.id == "verify_ssl")
        self.assertEqual(ssl_field.type, "enum")
        enum_values = [enum.value for enum in ssl_field.enum_values]
        self.assertIn("True", enum_values)
        self.assertIn("False", enum_values)

        # Verify SSL content field
        ssl_content_field = next(item for item in schema if item.id == "ssl_content")
        self.assertEqual(ssl_content_field.type, "multiline")
        self.assertTrue(ssl_content_field.is_secret)
        self.assertFalse(ssl_content_field.required)

    def test_plugin_metadata(self):
        """Test plugin metadata."""
        self.assertEqual(SaasPlugin.name, "JFrog User Password Rotation")
        self.assertEqual(
            SaasPlugin.summary, 
            "Change a user password in JFrog platform."
        )
        self.assertEqual(SaasPlugin.readme, "README.md")
        self.assertEqual(SaasPlugin.author, "Keeper Security")
        self.assertEqual(SaasPlugin.email, "pam@keepersecurity.com")

    @patch('jfrog_users.requests.Session')
    def test_session_caching(self, mock_session_class):
        """Test that session is cached."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        plugin = self.plugin()
        
        # Access session multiple times
        session1 = plugin.session
        session2 = plugin.session
        
        # Should be the same instance
        self.assertIs(session1, session2)
        
        # Session constructor should only be called once
        mock_session_class.assert_called_once()

    def test_verify_ssl_property(self):
        """Test verify_ssl property with different values."""
        # Test with "True" value
        field_values = {
            "Admin Access Token": DEFAULT_ACCESS_TOKEN,
            "JFrog URL": DEFAULT_JFROG_URL,
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }
        plugin = self.plugin(field_values=field_values)
        self.assertTrue(plugin.verify_ssl)

        # Test with "False" value
        field_values["Verify SSL"] = "False"
        plugin = self.plugin(field_values=field_values)
        self.assertFalse(plugin.verify_ssl)

    def test_cert_content_property(self):
        """Test cert_content access through get_config."""
        cert_data = DEFAULT_SSL_CERT
        field_values = {
            "Admin Access Token": DEFAULT_ACCESS_TOKEN,
            "JFrog URL": DEFAULT_JFROG_URL,
            "Verify SSL": "True",
            "SSL Certificate Content": cert_data
        }
        
        plugin = self.plugin(field_values=field_values)
        self.assertEqual(plugin.get_config("ssl_content"), cert_data)

    # ==================== Utility Function Tests ====================

    def test_url_validation_success_cases(self):
        """Test URL validation with valid URLs."""
        valid_urls = [
            "https://mycompany.jfrog.io",
            "http://jfrog.example.com",
            "https://artifactory.company.com",
            "http://127.0.0.1:8081"
        ]
        
        for url in valid_urls:
            with self.subTest(url=url):
                SaasPlugin.validate_jfrog_url(url)  # Should not raise

    def test_url_validation_failure_cases(self):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "jfrog.com",  # Missing protocol
            "",
            "https://",  # Missing netloc
        ]
        
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(SaasException) as context:
                    SaasPlugin.validate_jfrog_url(url)
                self.assertEqual("invalid_url", context.exception.codes[0]["code"])

    def test_should_verify_ssl_function(self):
        """Test the should_verify_ssl utility function."""
        # Test "True" values
        self.assertTrue(SaasPlugin.should_verify_ssl("True"))
        
        # Test "False" values
        self.assertFalse(SaasPlugin.should_verify_ssl("False"))
        self.assertFalse(SaasPlugin.should_verify_ssl("false"))
        self.assertFalse(SaasPlugin.should_verify_ssl(""))

    def test_ssl_context_disabled(self):
        """Test SSL context when SSL verification is disabled."""
        ssl_context = SaasPlugin.create_ssl_context(cert_content="", verify_ssl=False)
        self.assertIsNone(ssl_context)

    def test_ssl_context_enabled_no_cert(self):
        """Test SSL context when SSL is enabled but no custom cert."""
        ssl_context = SaasPlugin.create_ssl_context(cert_content="", verify_ssl=True)
        self.assertIsNone(ssl_context)

    def test_ssl_context_with_cert(self):
        """Test SSL context creation with custom certificate."""
        cert_content = DEFAULT_SSL_CERT
        
        with patch('ssl.create_default_context') as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            
            result = SaasPlugin.create_ssl_context(cert_content=cert_content, verify_ssl=True)
            
            mock_ssl.assert_called_once_with(cadata=cert_content.strip())
            self.assertEqual(mock_context, result)

    def test_ssl_context_invalid_cert(self):
        """Test SSL context creation with invalid certificate."""
        with patch('ssl.create_default_context') as mock_ssl:
            mock_ssl.side_effect = ssl.SSLError("Invalid certificate")
            
            with self.assertRaises(SaasException) as context:
                SaasPlugin.create_ssl_context(cert_content="invalid-cert", verify_ssl=True)
            self.assertEqual("invalid_ssl_cert", context.exception.codes[0]["code"])

    @patch('jfrog_users.tempfile.mkstemp')
    @patch('jfrog_users.os.fdopen')
    @patch('jfrog_users.atexit.register')
    def test_create_temp_cert_file(self, mock_atexit, mock_fdopen, mock_mkstemp):
        """Test temporary certificate file creation."""
        plugin = self.plugin()
        
        # Mock temp file creation
        mock_mkstemp.return_value = (123, '/tmp/jfrog_cert_abc.crt')
        mock_file = MagicMock()
        mock_fdopen.return_value.__enter__.return_value = mock_file

        cert_content = DEFAULT_SSL_CERT
        result = plugin._create_temp_cert_file(cert_content)
        
        self.assertEqual(result, '/tmp/jfrog_cert_abc.crt')
        mock_file.write.assert_called_once_with(cert_content.strip())
        mock_file.flush.assert_called_once()
        mock_atexit.assert_called_once()

    @patch('jfrog_users.os.path.exists')
    @patch('jfrog_users.os.unlink')
    def test_cleanup_temp_files(self, mock_unlink, mock_exists):
        """Test temporary file cleanup."""
        plugin = self.plugin()
        plugin._temp_cert_file = '/tmp/test_cert.crt'
        
        mock_exists.return_value = True
        
        plugin._cleanup_temp_files()
        
        mock_unlink.assert_called_once_with('/tmp/test_cert.crt')
        self.assertIsNone(plugin._temp_cert_file)

    @patch('jfrog_users.requests.Session')
    def test_health_check_failure(self, mock_session_class):
        """Test connection health check failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(500, text="Internal Server Error")
        mock_session.request.return_value = health_response

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._test_connection()
        
        self.assertIn("Cannot connect to JFrog platform", str(context.exception))

    def test_properties_access(self):
        """Test property accessors."""
        plugin = self.plugin()
        
        # Test jfrog_url property
        self.assertEqual(plugin.jfrog_url, DEFAULT_JFROG_URL)
        
        # Test admin_access_token property
        self.assertEqual(plugin.admin_access_token.value, DEFAULT_ACCESS_TOKEN)
        
        # Test verify_ssl property (should be True from default field values)
        self.assertTrue(plugin.verify_ssl)


if __name__ == '__main__':
    unittest.main()
