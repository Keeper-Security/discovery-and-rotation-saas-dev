from __future__ import annotations

import base64
import importlib.util
import json
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
from kdnrm.saas_type import SaasUser, ReturnCustomField, Field
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from jfrog_access_token import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    spec = importlib.util.spec_from_file_location(
        "jfrog_access_token",
        os.path.join(os.path.dirname(__file__), "jfrog_access_token.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SaasPlugin = module.SaasPlugin


# Test constants
DEFAULT_JFROG_URL = "https://mycompany.jfrog.io"
DEFAULT_ADMIN_TOKEN = "admin_token_12345"
DEFAULT_USER_TOKEN = None  # Token is created dynamically in create_user method to avoid security alerts
DEFAULT_SSL_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC...\n"
    "-----END CERTIFICATE-----"
)
DEFAULT_TOKEN_DESCRIPTION = "Test token description"
DEFAULT_TOKEN_SCOPE = "applied-permissions/user"


class JFrogAccessTokenTestBase(unittest.TestCase):
    """Base class for JFrog Access Token plugin tests."""

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
        access_token: str = None,
        token_description: str = DEFAULT_TOKEN_DESCRIPTION,
        token_scope: Optional[str] = None,
        fields: Optional[list] = None
    ):
        """Create a test user with the given parameters."""
        if access_token is None:
            access_token = JFrogAccessTokenTestUtils.create_jwt_token("testuser", DEFAULT_TOKEN_SCOPE)
        if fields is None:
            fields = [
                Field(type="secret", label="access_token", values=[access_token]),
                Field(type="text", label="token_description", values=[token_description]),
            ]
            if token_scope:
                fields.append(Field(type="text", label="jfrog_token_scope", values=[token_scope]))
        
        return SaasUser(
            username=Secret("testuser"),
            new_password=None,
            prior_password=None,
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


class JFrogAccessTokenTestUtils:
    """Utility methods for creating test data specific to the JFrog Access Token plugin."""

    @staticmethod
    def create_jfrog_config_fields(
        jfrog_url: str = DEFAULT_JFROG_URL,
        admin_token: str = DEFAULT_ADMIN_TOKEN,
        verify_ssl: str = "False",
        ssl_content: str = ""
    ) -> list:
        """Create config fields for the JFrog Access Token plugin."""
        return [
            {'type': 'url', 'label': 'JFrog URL', 'value': [jfrog_url]},
            {'type': 'secret', 'label': 'Admin Access Token', 'value': [admin_token]},
            {'type': 'enum', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]

    @staticmethod
    def create_jwt_token(username: str = "testuser", scope: str = DEFAULT_TOKEN_SCOPE) -> str:
        """Create a test JWT token with the given username and scope."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": f"fake_test_instance@fake123/users/{username}",
            "scp": scope,
            "aud": "fake_test_audience@fake123",
            "iss": "fake_test_issuer@fake123",
            "exp": 1697739600,
            "iat": 1697707000,
            "jti": "fake-test-jti-12345"
        }
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature = "fake_test_signature_for_testing_only"
        
        return f"fake_test_token_{header_b64}.{payload_b64}.{signature}"


# DEFAULT_USER_TOKEN is now created dynamically in create_user method


class JFrogAccessTokenPluginTest(JFrogAccessTokenTestBase):

    def plugin(
        self,
        access_token: str = None,
        token_description: str = DEFAULT_TOKEN_DESCRIPTION,
        token_scope: Optional[str] = None,
        field_values: Optional[dict] = None
    ):
        user = self.create_user(
            access_token=access_token,
            token_description=token_description,
            token_scope=token_scope
        )

        if field_values is None:
            field_values = {
                "Admin Access Token": DEFAULT_ADMIN_TOKEN,
                "JFrog URL": DEFAULT_JFROG_URL,
                "Verify SSL": "False",
                "SSL Certificate Content": ""
            }

        config_fields = JFrogAccessTokenTestUtils.create_jfrog_config_fields(
            jfrog_url=field_values.get("JFrog URL", DEFAULT_JFROG_URL),
            admin_token=field_values.get("Admin Access Token", DEFAULT_ADMIN_TOKEN),
            verify_ssl=field_values.get("Verify SSL", "False"),
            ssl_content=field_values.get("SSL Certificate Content", "")
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual(req_list[0], "requests")

    def test_plugin_metadata(self):
        """Test plugin metadata."""
        self.assertEqual(SaasPlugin.name, "JFrog Access Token")
        self.assertEqual(
            SaasPlugin.summary, 
            "Rotate JFrog access tokens for platform authentication."
        )
        self.assertEqual(SaasPlugin.readme, "README.md")
        self.assertEqual(SaasPlugin.author, "Keeper Security")
        self.assertEqual(SaasPlugin.email, "pam@keepersecurity.com")

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

    def test_can_rollback_property(self):
        """Test can_rollback property returns False."""
        plugin = self.plugin()
        self.assertFalse(plugin.can_rollback)

    # ==================== URL Validation Tests ====================

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

    # ==================== JWT Token Tests ====================

    def test_decode_jwt_payload_success(self):
        """Test successful JWT payload decoding."""
        token = JFrogAccessTokenTestUtils.create_jwt_token("testuser", "test-scope")
        payload = SaasPlugin._decode_jwt_payload(token)
        
        self.assertIn("sub", payload)
        self.assertIn("scp", payload)
        self.assertEqual(payload["scp"], "test-scope")

    def test_decode_jwt_payload_invalid_format(self):
        """Test JWT decoding with invalid token format."""
        invalid_tokens = [
            "invalid.token",  # Missing part
            "invalid",  # Not enough parts
            "invalid.token.signature.extra",  # Too many parts
        ]
        
        for token in invalid_tokens:
            with self.subTest(token=token):
                with self.assertRaises(SaasException):
                    SaasPlugin._decode_jwt_payload(token)

    def test_username_extraction_from_token(self):
        """Test username extraction from JWT token."""
        token = JFrogAccessTokenTestUtils.create_jwt_token("testuser123")
        plugin = self.plugin(access_token=token)
        
        username = plugin.username
        self.assertEqual(username, "testuser123")

    def test_username_extraction_invalid_subject(self):
        """Test username extraction with invalid subject format."""
        # Create token with invalid subject format
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "invalid-subject-format"}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token = f"{header_b64}.{payload_b64}.signature"
        
        plugin = self.plugin(access_token=token)
        
        with self.assertRaises(SaasException):
            _ = plugin.username

    def test_token_scope_from_user_field(self):
        """Test token scope extraction from user field."""
        plugin = self.plugin(token_scope="custom-scope")
        self.assertEqual(plugin.token_scope, "custom-scope")

    def test_token_scope_from_jwt(self):
        """Test token scope extraction from JWT token when user field is not provided."""
        token = JFrogAccessTokenTestUtils.create_jwt_token("testuser", "jwt-scope")
        plugin = self.plugin(access_token=token)
        self.assertEqual(plugin.token_scope, "jwt-scope")

    # ==================== SSL Tests ====================

    def test_should_verify_ssl_function(self):
        """Test the should_verify_ssl utility function."""
        self.assertTrue(SaasPlugin.should_verify_ssl("True"))
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

    @patch('jfrog_access_token.tempfile.mkstemp')
    @patch('jfrog_access_token.os.fdopen')
    @patch('jfrog_access_token.atexit.register')
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

    @patch('jfrog_access_token.os.path.exists')
    @patch('jfrog_access_token.os.unlink')
    def test_cleanup_temp_files(self, mock_unlink, mock_exists):
        """Test temporary file cleanup."""
        plugin = self.plugin()
        plugin._temp_cert_file = '/tmp/test_cert.crt'
        
        mock_exists.return_value = True
        
        plugin._cleanup_temp_files()
        
        mock_unlink.assert_called_once_with('/tmp/test_cert.crt')
        self.assertIsNone(plugin._temp_cert_file)

    # ==================== Session and Request Tests ====================

    @patch('jfrog_access_token.requests.Session')
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

    @patch('jfrog_access_token.requests.Session')
    def test_make_request_timeout(self, mock_session_class):
        """Test request timeout handling."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Timeout("Request timeout")

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._make_request('GET', '/test')
        
        self.assertIn("Request timeout to JFrog platform", str(context.exception))

    @patch('jfrog_access_token.requests.Session')
    def test_make_request_connection_error(self, mock_session_class):
        """Test connection error handling."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = ConnectionError("Connection failed")

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._make_request('GET', '/test')
        
        self.assertIn("Cannot connect to JFrog platform", str(context.exception))

    # ==================== Connection Test ====================

    @patch('jfrog_access_token.requests.Session')
    def test_connection_test_success(self, mock_session_class):
        """Test successful connection test."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(200)
        mock_session.request.return_value = health_response

        plugin = self.plugin()
        plugin._test_connection()  # Should not raise

    @patch('jfrog_access_token.requests.Session')
    def test_connection_test_failure(self, mock_session_class):
        """Test connection test failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        health_response = self.create_mock_response(500, text="Internal Server Error")
        mock_session.request.return_value = health_response

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._test_connection()
        
        self.assertIn("Cannot connect to JFrog platform", str(context.exception))

    # ==================== Token Verification Tests ====================

    @patch('jfrog_access_token.requests.Session')
    def test_verify_token_works_success(self, mock_session_class):
        """Test successful token verification."""
        # Mock the session that's created in the context manager
        mock_test_session = MagicMock()
        mock_test_session.get.return_value = self.create_mock_response(200)
        mock_test_session.verify = False  # Set verify attribute
        
        # Mock the context manager behavior
        mock_session_class.return_value.__enter__.return_value = mock_test_session
        mock_session_class.return_value.__exit__.return_value = None
        
        plugin = self.plugin()
        result = plugin._verify_token_works("test_token")
        self.assertTrue(result)

    @patch('jfrog_access_token.requests.Session')
    def test_verify_token_works_failure(self, mock_session_class):
        """Test token verification failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock the test session for token verification
        mock_test_session = MagicMock()
        mock_test_session.get.return_value = self.create_mock_response(401)
        
        with patch('jfrog_access_token.requests.Session', return_value=mock_test_session):
            plugin = self.plugin()
            result = plugin._verify_token_works("test_token")
            self.assertFalse(result)

    # ==================== Token Creation Tests ====================

    @patch('jfrog_access_token.requests.Session')
    def test_create_access_token_success(self, mock_session_class):
        """Test successful access token creation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        token_data = {
            "access_token": "new_token_12345",
            "token_id": "token_id_67890",
            "scope": "applied-permissions/user"
        }
        create_response = self.create_mock_response(200, token_data)
        mock_session.request.return_value = create_response

        plugin = self.plugin()
        result = plugin._create_access_token()
        
        self.assertEqual(result, token_data)

    @patch('jfrog_access_token.requests.Session')
    def test_create_access_token_authentication_failed(self, mock_session_class):
        """Test access token creation with authentication failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        create_response = self.create_mock_response(401)
        mock_session.request.return_value = create_response

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._create_access_token()
        
        self.assertIn("Authentication failed", str(context.exception))

    @patch('jfrog_access_token.requests.Session')
    def test_create_access_token_authorization_failed(self, mock_session_class):
        """Test access token creation with authorization failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        create_response = self.create_mock_response(403)
        mock_session.request.return_value = create_response

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._create_access_token()
        
        self.assertIn("Access denied", str(context.exception))

    # ==================== Token Revocation Tests ====================

    @patch('jfrog_access_token.requests.Session')
    def test_revoke_access_token_success(self, mock_session_class):
        """Test successful access token revocation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        revoke_response = self.create_mock_response(200)
        mock_session.request.return_value = revoke_response

        plugin = self.plugin()
        plugin._revoke_access_token("test_token")  # Should not raise

    @patch('jfrog_access_token.requests.Session')
    def test_revoke_access_token_not_found(self, mock_session_class):
        """Test access token revocation when token not found."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        revoke_response = self.create_mock_response(404)
        mock_session.request.return_value = revoke_response

        plugin = self.plugin()
        plugin._revoke_access_token("test_token")  # Should not raise (warning logged)

    @patch('jfrog_access_token.requests.Session')
    def test_revoke_access_token_authentication_failed(self, mock_session_class):
        """Test access token revocation with authentication failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        revoke_response = self.create_mock_response(401)
        mock_session.request.return_value = revoke_response

        plugin = self.plugin()

        with self.assertRaises(SaasException) as context:
            plugin._revoke_access_token("test_token")
        
        self.assertIn("Authentication failed", str(context.exception))

    def test_revoke_access_token_empty_token(self):
        """Test access token revocation with empty token."""
        plugin = self.plugin()
        plugin._revoke_access_token("")  # Should not raise (warning logged)
        plugin._revoke_access_token(None)  # Should not raise (warning logged)

    # ==================== Full Token Rotation Tests ====================

    @patch('jfrog_access_token.requests.Session')
    def test_rotate_api_key_success(self, mock_session_class):
        """Test successful complete token rotation."""
        # Mock the main session for API calls
        mock_session = MagicMock()
        
        # Mock responses for health check, token creation, and revocation
        health_response = self.create_mock_response(200)
        token_data = {
            "access_token": "new_token_12345",
            "token_id": "token_id_67890",
            "scope": "applied-permissions/user"
        }
        create_response = self.create_mock_response(200, token_data)
        revoke_response = self.create_mock_response(200)

        mock_session.request.side_effect = [health_response, create_response, revoke_response]

        # Mock token verification session (used in context manager)
        mock_test_session = MagicMock()
        mock_test_session.get.return_value = self.create_mock_response(200)
        mock_test_session.verify = False  # Set verify attribute
        
        # Set up the Session class to return different instances
        def session_side_effect():
            if not hasattr(session_side_effect, 'call_count'):
                session_side_effect.call_count = 0
            session_side_effect.call_count += 1
            
            if session_side_effect.call_count == 1:
                # First call is for the main plugin session
                return mock_session
            else:
                # Second call is for token verification (context manager)
                mock_ctx = MagicMock()
                mock_ctx.__enter__.return_value = mock_test_session
                mock_ctx.__exit__.return_value = None
                return mock_ctx
        
        mock_session_class.side_effect = session_side_effect
        
        plugin = self.plugin()
        plugin.change_password()

        # Verify return fields were added
        self.assertEqual(len(plugin.return_fields), 3)
        
        # Check access_token field
        access_token_field = next(f for f in plugin.return_fields if f.label == "access_token")
        self.assertEqual(access_token_field.value.value, "new_token_12345")
        
        # Check token_id field
        token_id_field = next(f for f in plugin.return_fields if f.label == "jfrog_token_id")
        self.assertEqual(token_id_field.value.value, "token_id_67890")
        
        # Check scope field
        scope_field = next(f for f in plugin.return_fields if f.label == "jfrog_token_scope")
        self.assertEqual(scope_field.value.value, "applied-permissions/user")

    @patch('jfrog_access_token.requests.Session')
    def test_rotate_api_key_token_verification_fails(self, mock_session_class):
        """Test token rotation when new token verification fails."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock responses for health check and token creation
        health_response = self.create_mock_response(200)
        token_data = {"access_token": "new_token_12345"}
        create_response = self.create_mock_response(200, token_data)

        mock_session.request.side_effect = [health_response, create_response]

        # Mock token verification failure
        mock_test_session = MagicMock()
        mock_test_session.get.return_value = self.create_mock_response(401)
        
        with patch('jfrog_access_token.requests.Session', side_effect=[mock_session, mock_test_session]):
            plugin = self.plugin()
            
            with self.assertRaises(SaasException) as context:
                plugin.change_password()
            
            self.assertIn("New access token verification failed", str(context.exception))

    @patch('jfrog_access_token.requests.Session')
    def test_rotate_api_key_no_token_returned(self, mock_session_class):
        """Test token rotation when no token is returned from API."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock responses for health check and token creation (no access_token in response)
        health_response = self.create_mock_response(200)
        token_data = {"token_id": "token_id_67890"}  # Missing access_token
        create_response = self.create_mock_response(200, token_data)

        mock_session.request.side_effect = [health_response, create_response]

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("No access token returned from JFrog API", str(context.exception))

    @patch('jfrog_access_token.requests.Session')
    def test_rotate_api_key_revocation_fails_gracefully(self, mock_session_class):
        """Test that token rotation continues even if revocation fails."""
        # Mock the main session for API calls
        mock_session = MagicMock()

        # Mock responses for health check, token creation, and failed revocation
        health_response = self.create_mock_response(200)
        token_data = {"access_token": "new_token_12345"}
        create_response = self.create_mock_response(200, token_data)
        revoke_response = self.create_mock_response(500, text="Server Error")

        mock_session.request.side_effect = [health_response, create_response, revoke_response]

        # Mock token verification session (used in context manager)
        mock_test_session = MagicMock()
        mock_test_session.get.return_value = self.create_mock_response(200)
        mock_test_session.verify = False  # Set verify attribute
        
        # Set up the Session class to return different instances
        def session_side_effect():
            if not hasattr(session_side_effect, 'call_count'):
                session_side_effect.call_count = 0
            session_side_effect.call_count += 1
            
            if session_side_effect.call_count == 1:
                # First call is for the main plugin session
                return mock_session
            else:
                # Second call is for token verification (context manager)
                mock_ctx = MagicMock()
                mock_ctx.__enter__.return_value = mock_test_session
                mock_ctx.__exit__.return_value = None
                return mock_ctx
        
        mock_session_class.side_effect = session_side_effect
        
        plugin = self.plugin()
        plugin.change_password()  # Should complete successfully despite revocation failure

        # Verify return fields were still added
        self.assertEqual(len(plugin.return_fields), 1)
        access_token_field = plugin.return_fields[0]
        self.assertEqual(access_token_field.label, "access_token")
        self.assertEqual(access_token_field.value.value, "new_token_12345")

    # ==================== Rollback Tests ====================

    def test_rollback_api_key_not_supported(self):
        """Test that rollback is not supported."""
        plugin = self.plugin()
        plugin.rollback_password()  # Should not raise, just log

    # ==================== Property Access Tests ====================

    def test_jfrog_url_property(self):
        """Test jfrog_url property."""
        plugin = self.plugin()
        self.assertEqual(plugin.jfrog_url, DEFAULT_JFROG_URL)

    def test_admin_access_token_property(self):
        """Test admin_access_token property."""
        plugin = self.plugin()
        self.assertEqual(plugin.admin_access_token.value, DEFAULT_ADMIN_TOKEN)

    def test_verify_ssl_property(self):
        """Test verify_ssl property with different values."""
        # Test with "False" value
        field_values = {
            "Admin Access Token": DEFAULT_ADMIN_TOKEN,
            "JFrog URL": DEFAULT_JFROG_URL,
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }
        plugin = self.plugin(field_values=field_values)
        self.assertFalse(plugin.verify_ssl)

        # Test with "True" value
        field_values["Verify SSL"] = "True"
        plugin = self.plugin(field_values=field_values)
        self.assertTrue(plugin.verify_ssl)

    def test_current_access_token_property(self):
        """Test current_access_token property."""
        test_token = "test_access_token_123"
        plugin = self.plugin(access_token=test_token)
        self.assertEqual(plugin.current_access_token, test_token)

    def test_current_access_token_missing(self):
        """Test current_access_token property when token is missing."""
        user = SaasUser(
            username=Secret("testuser"),
            new_password=None,
            prior_password=None,
            fields=[]  # No access_token field
        )
        
        config_fields = JFrogAccessTokenTestUtils.create_jfrog_config_fields()
        config_record = self.create_config_record(config_fields)
        plugin = SaasPlugin(user=user, config_record=config_record)

        with self.assertRaises(SaasException) as context:
            _ = plugin.current_access_token
        
        self.assertEqual("access_token", context.exception.codes[0]["code"])

    def test_get_token_description_missing(self):
        """Test get_token_description property when description is missing."""
        user = SaasUser(
            username=Secret("testuser"),
            new_password=None,
            prior_password=None,
            fields=[
                Field(type="secret", label="access_token", values=[DEFAULT_USER_TOKEN])
                # Missing token_description field
            ]
        )
        
        config_fields = JFrogAccessTokenTestUtils.create_jfrog_config_fields()
        config_record = self.create_config_record(config_fields)
        plugin = SaasPlugin(user=user, config_record=config_record)

        with self.assertRaises(SaasException) as context:
            _ = plugin.get_token_description
        
        self.assertEqual("token_description", context.exception.codes[0]["code"])

    # ==================== Username Validation Tests ====================

    def test_validate_username_success(self):
        """Test successful username validation."""
        plugin = self.plugin()
        plugin._validate_username("testuser")  # Should not raise
        plugin._validate_username("a")  # Minimum length
        plugin._validate_username("a" * 128)  # Maximum length

    def test_validate_username_failure(self):
        """Test username validation failure."""
        plugin = self.plugin()
        
        # Empty username
        with self.assertRaises(SaasException):
            plugin._validate_username("")
        
        # Too long username
        with self.assertRaises(SaasException):
            plugin._validate_username("a" * 129)

    # ==================== Add Return Field Tests ====================

    def test_add_return_field(self):
        """Test adding return fields."""
        plugin = self.plugin()
        
        field = ReturnCustomField(
            label="test_field",
            type="secret",
            value=Secret("test_value")
        )
        
        plugin.add_return_field(field)
        self.assertEqual(len(plugin.return_fields), 1)
        self.assertEqual(plugin.return_fields[0], field)


if __name__ == '__main__':
    unittest.main()