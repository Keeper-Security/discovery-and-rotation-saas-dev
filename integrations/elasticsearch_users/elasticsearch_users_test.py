from __future__ import annotations
import unittest
import sys
import os

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from elasticsearch_users import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "elasticsearch_users", 
        os.path.join(os.path.dirname(__file__), "elasticsearch_users.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SaasPlugin = module.SaasPlugin
from unittest.mock import MagicMock, patch
from plugin_dev.test_base import MockRecord
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from typing import Optional



# Test constants
DEFAULT_ELASTICSEARCH_URL = "https://localhost:9200"
DEFAULT_SSL_CERT = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
DEFAULT_USERNAME = "testuser"
DEFAULT_NEW_PASSWORD = "NewPassword123!"
DEFAULT_PRIOR_PASSWORD = "OldPassword123!"


class ElasticsearchTestBase(unittest.TestCase):
    """Base class for Elasticsearch plugin tests."""

    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")

    def create_mock_elasticsearch_client(self, mock_elasticsearch_class):
        """Create a mock Elasticsearch client that behaves correctly."""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_elasticsearch_class.return_value = mock_client
        return mock_client

    def create_user(self, username: str, new_password: str, prior_password: Optional[str] = None, fields: Optional[list] = None):
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

    def create_field(self, field_type: str, label: str, value: str, is_secret: bool = False):
        """Create a configuration field."""
        return {
            'type': 'secret' if is_secret else field_type,
            'label': label,
            'value': [value]
        }


class ElasticsearchUsersTestUtils:
    """Utility methods for creating test data specific to the Users plugin."""

    @staticmethod
    def create_users_config_fields(elasticsearch_url: str = DEFAULT_ELASTICSEARCH_URL,
                                   api_key: str = "test_api_key_12345",
                                   verify_ssl: str = "False",
                                   ssl_content: str = "") -> list:
        """Create config fields for the Users plugin."""
        return [
            {'type': 'url', 'label': 'Elasticsearch URL', 'value': [elasticsearch_url]},
            {'type': 'secret', 'label': 'API Key', 'value': [api_key]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]


class ElasticsearchUserPluginTest(ElasticsearchTestBase):

    def plugin(self,
               prior_password: Optional[Secret] = None,
               field_values: Optional[dict] = None,
               username: Optional[Secret] = None):

        if username is None:
            username = Secret("testuser")

        user = self.create_user(
            username=username.value,
            new_password="NewPassword123!",
            prior_password=prior_password.value if prior_password else None
        )

        if field_values is None:
            field_values = {
                "API Key": "test_api_key_12345",
                "Elasticsearch URL": DEFAULT_ELASTICSEARCH_URL,
                "Verify SSL": "True",
                "SSL Certificate Content": ""
            }

        config_fields = ElasticsearchUsersTestUtils.create_users_config_fields(
            elasticsearch_url=field_values.get("Elasticsearch URL", DEFAULT_ELASTICSEARCH_URL),
            api_key=field_values.get("API Key", "test_api_key_12345"),
            verify_ssl=field_values.get("Verify SSL", "True"),
            ssl_content=field_values.get("SSL Certificate Content", "")
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual(req_list[0], "elasticsearch")

    def test_change_password_success_https(self):
        """Test successful password change with HTTPS connection."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = self.create_mock_elasticsearch_client(mock_client_class)
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}

            plugin = self.plugin()
            plugin.change_password()

            # Verify client was called correctly
            mock_client_class.assert_called_once()
            mock_client.ping.assert_called_once()
            mock_client.security.get_user.assert_called_with(username="testuser")
            mock_client.security.change_password.assert_called_with(
                username="testuser",
                password="NewPassword123!"
            )

    def test_change_password_success_ssl_disabled(self):
        """Test successful password change with SSL verification disabled."""
        field_values = {
            "API Key": "test_api_key_12345",
            "Elasticsearch URL": DEFAULT_ELASTICSEARCH_URL,
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }

        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = self.create_mock_elasticsearch_client(mock_client_class)
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify SSL verification was disabled
            call_args = mock_client_class.call_args[1]
            self.assertFalse(call_args['verify_certs'])
            self.assertNotIn('ssl_context', call_args)

    def test_change_password_success_with_custom_cert(self):
        """Test successful password change with custom SSL certificate."""
        field_values = {
            "API Key": "test_api_key_12345",
            "Elasticsearch URL": "https://localhost:9200",
            "Verify SSL": "True",
            "SSL Certificate Content": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        }

        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

            with patch("ssl.create_default_context") as mock_ssl:
                mock_ssl_context = MagicMock()
                mock_ssl.return_value = mock_ssl_context

                plugin = self.plugin(field_values=field_values)
                plugin.change_password()

                # Verify custom SSL context was used
                call_args = mock_client_class.call_args[1]
                self.assertTrue(call_args['verify_certs'])
                self.assertIn('ssl_context', call_args)
                mock_ssl.assert_called_once()

    def test_change_password_success_ssl_enabled_no_cert(self):
        """Test successful password change with SSL enabled but no custom certificate."""
        field_values = {
            "API Key": "test_api_key_12345",
            "Elasticsearch URL": "https://localhost:9200",
            "Verify SSL": "True",
            "SSL Certificate Content": ""
        }

        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify SSL verification was enabled but no custom context
            call_args = mock_client_class.call_args[1]
            self.assertTrue(call_args['verify_certs'])
            self.assertNotIn('ssl_context', call_args)

    def test_change_password_fail_user_not_found(self):
        """Test password change when user doesn't exist."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.side_effect = Exception("User not found")
            mock_client_class.return_value = mock_client

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Failed to verify user existence", str(err))

    def test_change_password_fail_connection_error(self):
        """Test password change with connection failure."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client_class.side_effect = ESConnectionError("Connection failed")

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Connection failed", str(err))

    def test_change_password_fail_ping_failure(self):
        """Test password change when ping fails."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = False
            mock_client_class.return_value = mock_client

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Unable to connect to Elasticsearch server", str(err))

    def test_change_password_fail_no_new_password(self):
        """Test password change when no new password is provided."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = self.create_mock_elasticsearch_client(mock_client_class)
            
            user = SaasUser(
                username=Secret("testuser"),
                new_password=None,
                prior_password=None
            )

            config_record = MockRecord(
                custom=[
                    {'type': 'secret', 'label': 'API Key', 'value': ["test_api_key_12345"]},
                    {'type': 'url', 'label': 'Elasticsearch URL', 'value': ["https://localhost:9200"]},
                    {'type': 'text', 'label': 'Verify SSL', 'value': ["True"]},
                    {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [""]},
                ]
            )

            plugin = SaasPlugin(user=user, config_record=config_record)

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("No new password provided", str(err))

    def test_can_rollback_initial_state(self):
        """Test can_rollback property returns False initially."""
        plugin = self.plugin()
        self.assertFalse(plugin.can_rollback)

    def test_can_rollback_after_user_verification(self):
        """Test can_rollback property returns True after successful user verification."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client_class.return_value = mock_client

            plugin = self.plugin()
            plugin._verify_user_exists()
            
            self.assertTrue(plugin.can_rollback)

    def test_rollback_success(self):
        """Test successful password rollback."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

            plugin = self.plugin(prior_password=Secret("OldPassword123!"))
            plugin.rollback_password()

            # Verify rollback was called with prior password
            mock_client.security.change_password.assert_called_with(
                username="testuser",
                password="OldPassword123!"
            )

    def test_rollback_fail_no_prior_password(self):
        """Test rollback failure when no prior password is available."""
        plugin = self.plugin()

        try:
            plugin.rollback_password()
            self.fail("Should have failed")
        except Exception as err:
            self.assertIn("No prior password available", str(err))

    def test_config_schema(self):
        """Test configuration schema."""
        schema = SaasPlugin.config_schema()
        
        # Verify required fields
        field_ids = [item.id for item in schema]
        expected_fields = ["api_key", "elasticsearch_url", "verify_ssl", "ssl_content"]
        
        for field in expected_fields:
            self.assertIn(field, field_ids)
        
        # Verify api_key is secret
        api_key_field = next(item for item in schema if item.id == "api_key")
        self.assertTrue(api_key_field.is_secret)
        
        # Verify URL field type
        url_field = next(item for item in schema if item.id == "elasticsearch_url")
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
        self.assertEqual(SaasPlugin.name, "Elasticsearch User")
        self.assertEqual(SaasPlugin.summary, "Change a user password in Elasticsearch.")
        self.assertEqual(SaasPlugin.readme, "README.md")
        self.assertEqual(SaasPlugin.author, "Keeper Security")
        self.assertEqual(SaasPlugin.email, "pam@keepersecurity.com")

    def test_client_creation_caching(self):
        """Test that Elasticsearch client is cached."""
        with patch("elasticsearch_users.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client_class.return_value = mock_client

            plugin = self.plugin()
            
            # Access client multiple times
            client1 = plugin.client
            client2 = plugin.client
            
            # Should be the same instance
            self.assertIs(client1, client2)
            
            # Elasticsearch constructor should only be called once
            mock_client_class.assert_called_once()

    def test_verify_ssl_property(self):
        """Test verify_ssl property with different values."""
        # Test with "True" value
        field_values = {"API Key": "test", "Elasticsearch URL": "https://localhost:9200", 
                       "Verify SSL": "True", "SSL Certificate Content": ""}
        plugin = self.plugin(field_values=field_values)
        self.assertTrue(plugin.verify_ssl)

        # Test with "False" value
        field_values["Verify SSL"] = "False"
        plugin = self.plugin(field_values=field_values)
        self.assertFalse(plugin.verify_ssl)

        # Test with empty value
        field_values["Verify SSL"] = ""
        plugin = self.plugin(field_values=field_values)
        self.assertFalse(plugin.verify_ssl)
        
        # Test with None value (field not present)
        # Create a plugin manually without the Verify SSL field
        user = self.create_user(
            username="testuser",
            new_password="NewPassword123!",
            prior_password=None
        )
        
        # Create MockRecord without the verify_ssl field
        config_record = MockRecord(
            custom=[
                {'type': 'secret', 'label': 'API Key', 'value': ["test_api_key_12345"]},
                {'type': 'url', 'label': 'Elasticsearch URL', 'value': [DEFAULT_ELASTICSEARCH_URL]},
                {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [""]},
                # Note: No 'Verify SSL' field - it's completely missing
            ]
        )
        
        plugin = SaasPlugin(user=user, config_record=config_record)
        self.assertFalse(plugin.verify_ssl)

    def test_cert_content_property(self):
        """Test cert_content access through get_config."""
        cert_data = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        field_values = {
            "API Key": "test", 
            "Elasticsearch URL": "https://localhost:9200", 
            "Verify SSL": "True", 
            "SSL Certificate Content": cert_data
        }
        
        plugin = self.plugin(field_values=field_values)
        self.assertEqual(plugin.get_config("ssl_content"), cert_data)

    # ==================== Utility Function Tests ====================

    def test_url_validation_success_cases(self):
        """Test URL validation with valid URLs."""
        valid_urls = [
            "https://localhost:9200",
            "http://elasticsearch.example.com:9200",
            "https://es.company.com",
            "http://127.0.0.1:9200"
        ]
        
        for url in valid_urls:
            with self.subTest(url=url):
                SaasPlugin.validate_elasticsearch_url(url)  # Should not raise

    def test_url_validation_failure_cases(self):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "elasticsearch.com",  # Missing protocol
            "",
            "https://",  # Missing netloc
        ]
        
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(SaasException) as context:
                    SaasPlugin.validate_elasticsearch_url(url)
                self.assertEqual("invalid_url", context.exception.codes[0]["code"])

    def test_should_verify_ssl_function(self):
        """Test the should_verify_ssl utility function."""
        # Test "True" values
        self.assertTrue(SaasPlugin.should_verify_ssl("True"))
        
        # Test "False" values
        self.assertFalse(SaasPlugin.should_verify_ssl("False"))
        self.assertFalse(SaasPlugin.should_verify_ssl("false"))
        self.assertFalse(SaasPlugin.should_verify_ssl(""))
        self.assertFalse(SaasPlugin.should_verify_ssl(None))

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
        cert_content = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        
        with patch('ssl.create_default_context') as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            
            result = SaasPlugin.create_ssl_context(cert_content=cert_content, verify_ssl=True)
            
            mock_ssl.assert_called_once_with(cadata=cert_content)
            self.assertEqual(mock_context, result)

    def test_ssl_context_invalid_cert(self):
        """Test SSL context creation with invalid certificate."""
        with patch('ssl.create_default_context') as mock_ssl:
            import ssl as ssl_module
            mock_ssl.side_effect = ssl_module.SSLError("Invalid certificate")
            
            with self.assertRaises(SaasException) as context:
                SaasPlugin.create_ssl_context(cert_content="invalid-cert", verify_ssl=True)
            self.assertEqual("invalid_ssl_cert", context.exception.codes[0]["code"])

    def test_build_elasticsearch_client_config_api_key(self):
        """Test building Elasticsearch client config with API key."""
        config = SaasPlugin.build_elasticsearch_client_config(
            hosts=["https://localhost:9200"],
            verify_ssl=False,
            api_key="test_api_key"
        )
        
        expected_config = {
            "hosts": ["https://localhost:9200"],
            "verify_certs": False,
            "request_timeout": 30,
            "retry_on_timeout": True,
            "max_retries": 3,
            "api_key": "test_api_key"
        }
        
        self.assertEqual(config, expected_config)

    def test_build_elasticsearch_client_config_basic_auth(self):
        """Test building Elasticsearch client config with basic auth."""
        config = SaasPlugin.build_elasticsearch_client_config(
            hosts=["https://localhost:9200"],
            verify_ssl=True,
            basic_auth=("username", "password")
        )
        
        self.assertEqual(config["basic_auth"], ("username", "password"))
        self.assertTrue(config["verify_certs"])

    def test_build_elasticsearch_client_config_invalid_auth(self):
        """Test building client config with invalid auth configuration."""
        # Test both API key and basic auth provided
        with self.assertRaises(SaasException) as context:
            SaasPlugin.build_elasticsearch_client_config(
                hosts=["https://localhost:9200"],
                verify_ssl=False,
                api_key="test_key",
                basic_auth=("user", "pass")
            )
        self.assertEqual("invalid_auth_config", context.exception.codes[0]["code"])

        # Test neither API key nor basic auth provided
        with self.assertRaises(SaasException) as context:
            SaasPlugin.build_elasticsearch_client_config(
                hosts=["https://localhost:9200"],
                verify_ssl=False
            )
        self.assertEqual("missing_auth_config", context.exception.codes[0]["code"])


if __name__ == '__main__':
    unittest.main()
