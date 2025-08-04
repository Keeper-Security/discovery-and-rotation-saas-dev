from __future__ import annotations
import unittest
import sys
import os
from unittest.mock import MagicMock, patch
from plugin_dev.test_base import MockRecord
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, Field
from kdnrm.exceptions import SaasException
from elasticsearch.exceptions import ConflictError, NotFoundError, AuthenticationException
from typing import Optional, Dict, Any

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from elasticsearch_serviceaccount_token import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    import importlib.util
    import elasticsearch_serviceaccount_token
    spec = importlib.util.spec_from_file_location(
        "elasticsearch_serviceaccount_token", 
        os.path.join(os.path.dirname(__file__), "elasticsearch_serviceaccount_token.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SaasPlugin = module.SaasPlugin

# Test constants
DEFAULT_ELASTICSEARCH_URL = "https://localhost:9200"
DEFAULT_USERNAME = "testuser"


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


class ElasticsearchServiceAccountTestUtils:
    """Utility methods for creating test data specific to the Service Account plugin."""

    @staticmethod
    def create_service_account_config_fields(elasticsearch_url: str = DEFAULT_ELASTICSEARCH_URL,
                                           api_key: str = "test_api_key",
                                           namespace: str = "elastic",
                                           service: str = "fleet-server",
                                           verify_ssl: str = "False",
                                           ssl_content: str = "") -> list:
        """Create config fields for the Service Account plugin."""
        return [
            {'type': 'url', 'label': 'Elasticsearch URL', 'value': [elasticsearch_url]},
            {'type': 'secret', 'label': 'API Key', 'value': [api_key]},
            {'type': 'text', 'label': 'Service Account Namespace', 'value': [namespace]},
            {'type': 'text', 'label': 'Service Account Service', 'value': [service]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]

    @staticmethod
    def create_token_name_field(token_name: str) -> Field:
        """Create a token_name field for user fields."""
        return Field(
            label="token_name",
            type="text",
            values=[token_name]
        )


class ElasticsearchServiceAccountTokenTest(ElasticsearchTestBase):
    """Test suite for Elasticsearch Service Account Token SaaS plugin."""

    def setUp(self):
        """Set up test environment before each test."""
        super().setUp()
        
        # Default token name for user fields
        self.default_token_name = 'test-token'

    def create_plugin(self, config_overrides: Optional[Dict[str, str]] = None, 
                     prior_password: Optional[Secret] = None,
                     token_name: Optional[str] = "DEFAULT") -> SaasPlugin:
        """
        Create a SaasPlugin instance with test configuration.
        
        Args:
            config_overrides: Override default config values
            prior_password: Prior password for user
            token_name: Token name for user fields
            
        Returns:
            Configured SaasPlugin instance
        """
        # Create user fields with token_name
        user_fields = []
        if token_name == "DEFAULT":
            # Use default token name
            user_fields.append(ElasticsearchServiceAccountTestUtils.create_token_name_field(self.default_token_name))
        elif token_name is not None:
            # Use provided token name
            user_fields.append(ElasticsearchServiceAccountTestUtils.create_token_name_field(token_name))
        # If token_name is None, don't create any fields
        
        user = self.create_user(
            username=DEFAULT_USERNAME,
            new_password="dummy-password-not-used",
            prior_password=prior_password.value if prior_password else "old-dummy-password",
            fields=user_fields
        )

        # Create config with defaults and overrides
        elasticsearch_url = config_overrides.get('elasticsearch_url', DEFAULT_ELASTICSEARCH_URL) if config_overrides else DEFAULT_ELASTICSEARCH_URL
        api_key = config_overrides.get('api_key', 'test_api_key') if config_overrides else 'test_api_key'
        namespace = config_overrides.get('namespace', 'elastic') if config_overrides else 'elastic'
        service = config_overrides.get('service', 'fleet-server') if config_overrides else 'fleet-server'
        verify_ssl = config_overrides.get('verify_ssl', 'False') if config_overrides else 'False'
        ssl_content = config_overrides.get('ssl_content', '') if config_overrides else ''

        config_fields = ElasticsearchServiceAccountTestUtils.create_service_account_config_fields(
            elasticsearch_url=elasticsearch_url,
            api_key=api_key,
            namespace=namespace,
            service=service,
            verify_ssl=verify_ssl,
            ssl_content=ssl_content
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def assert_client_initialization(self, mock_elasticsearch: MagicMock, expected_config: Dict[str, Any]):
        """
        Assert that Elasticsearch client was initialized with correct parameters.
        
        Args:
            mock_elasticsearch: Mocked Elasticsearch class
            expected_config: Expected configuration parameters
        """
        expected_call_kwargs = {
            'hosts': [expected_config.get('hosts', 'https://localhost:9200')],
            'api_key': expected_config.get('api_key', 'test_api_key'),
            'verify_certs': expected_config.get('verify_certs', False),
            'request_timeout': 30,
            'retry_on_timeout': True,
            'max_retries': 3,
        }
        
        # Only include ssl_context if it's not None
        ssl_context = expected_config.get('ssl_context')
        if ssl_context is not None:
            expected_call_kwargs['ssl_context'] = ssl_context
            
        mock_elasticsearch.assert_called_once_with(**expected_call_kwargs)

    def test_plugin_metadata(self):
        """Test plugin basic metadata and requirements."""
        # Test requirements
        req_list = SaasPlugin.requirements()
        self.assertEqual(["elasticsearch"], req_list)
        
        # Test metadata
        self.assertEqual("Elasticsearch Service Account Token", SaasPlugin.name)
        self.assertEqual("Keeper Security", SaasPlugin.author)
        self.assertEqual("README.md", SaasPlugin.readme)
        self.assertFalse(self.create_plugin().can_rollback)

    def test_config_schema_structure(self):
        """Test configuration schema structure and field definitions."""
        schema = SaasPlugin.config_schema()
        
        # Verify schema size and required fields (token_name is in user fields, not config)
        self.assertEqual(6, len(schema))
        required_fields = [item for item in schema if item.required]
        self.assertEqual(4, len(required_fields))
        
        # Verify all expected field IDs are present
        field_ids = {item.id for item in schema}
        expected_ids = {"elasticsearch_url", "api_key", "namespace", "service", "verify_ssl", "ssl_content"}
        self.assertEqual(expected_ids, field_ids)
        
        # Verify specific field configurations
        api_key_field = next(item for item in schema if item.id == "api_key")
        self.assertTrue(api_key_field.is_secret)
        self.assertTrue(api_key_field.required)

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

    def test_token_name_validation_success_cases(self):
        """Test token name validation with valid names."""
        plugin = self.create_plugin()
        
        valid_names = [
            "valid-token",
            "Token123",
            "my_token",
            "a",  # Minimum length
            "a" * 256,  # Maximum length
            "test-token_123"
        ]
        
        for name in valid_names:
            with self.subTest(name=name):
                plugin._validate_token_name(name)  # Should not raise

    def test_token_name_validation_failure_cases(self):
        """Test token name validation with invalid names."""
        plugin = self.create_plugin()
        
        invalid_names = [
            ("_invalid-name", "cannot begin with an underscore"),
            ("invalid@name", "can only contain alphanumeric"),
            ("token with spaces", "can only contain alphanumeric"),
            ("", "must be between 1 and 256 characters"),
            ("a" * 257, "must be between 1 and 256 characters"),
            ("token/slash", "can only contain alphanumeric"),
        ]
        
        for name, expected_error in invalid_names:
            with self.subTest(name=name):
                with self.assertRaises(SaasException) as context:
                    plugin._validate_token_name(name)
                self.assertEqual("invalid_token_name", context.exception.codes[0]["code"])

    # ==================== Client Connection Tests ====================

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_client_initialization_default_config(self, mock_elasticsearch):
        """Test Elasticsearch client initialization with default configuration."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        plugin = self.create_plugin()
        client = plugin.client
        
        self.assert_client_initialization(mock_elasticsearch, {
            'hosts': 'https://localhost:9200',
            'api_key': 'test_api_key',
            'verify_certs': False,
            'ssl_context': None
        })
        
        mock_client.ping.assert_called_once()

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_client_initialization_ssl_enabled(self, mock_elasticsearch):
        """Test client initialization with SSL verification enabled."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        plugin = self.create_plugin({'verify_ssl': 'True'})
        client = plugin.client
        
        self.assert_client_initialization(mock_elasticsearch, {
            'verify_certs': True,
            'ssl_context': None
        })

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_client_connection_failure(self, mock_elasticsearch):
        """Test handling of client connection failures."""
        mock_elasticsearch.side_effect = Exception("Connection failed")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertEqual("elasticsearch_connection_error", context.exception.codes[0]["code"])
        self.assertIn("Connection failed", str(context.exception))

    # ==================== Token Creation Tests ====================

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_successful_token_creation(self, mock_elasticsearch):
        """Test successful service account token creation."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.create_service_token.return_value = {
            "created": True,
            "token": {
                "name": "test-token",
                "value": "AAEAAWVsYXN0aWM...test-token-value"
            }
        }
        
        plugin = self.create_plugin()
        plugin.change_password()
        
        # Verify API call
        mock_client.security.create_service_token.assert_called_once_with(
            namespace="elastic",
            service="fleet-server",
            name="test-token"
        )
        
        # Verify return fields
        self.assertEqual(2, len(plugin.return_fields))
        
        token_field = next((f for f in plugin.return_fields if f.label == "Service Account Token"), None)
        self.assertIsNotNone(token_field)
        self.assertEqual("AAEAAWVsYXN0aWM...test-token-value", token_field.value.value)

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_token_creation_with_custom_config(self, mock_elasticsearch):
        """Test token creation with custom configuration."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.create_service_token.return_value = {
            "created": True,
            "token": {"name": "custom-token", "value": "custom-token-value"}
        }
        
        custom_config = {
            'namespace': 'custom',
            'service': 'my-service'
        }
        
        plugin = self.create_plugin(custom_config, token_name='custom-token')
        plugin.change_password()
        
        mock_client.security.create_service_token.assert_called_once_with(
            namespace="custom",
            service="my-service",
            name="custom-token"
        )

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_elasticsearch_error_scenarios(self, mock_elasticsearch):
        """Test handling of various Elasticsearch errors."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        error_scenarios = [
            (ConflictError("Conflict", {}, {}), "token_already_exists", "already exists"),
            (NotFoundError("Not Found", {}, {}), "service_account_not_found", "not found"),
            (AuthenticationException("Auth Failed", {}, {}), "authentication_failed", "Authentication failed"),
            (Exception("Generic error"), "elasticsearch_error", "Failed to create service account token")
        ]
        
        for exception, expected_code, expected_message in error_scenarios:
            with self.subTest(exception=type(exception).__name__):
                mock_client.security.create_service_token.side_effect = exception
                plugin = self.create_plugin()
                
                with self.assertRaises(SaasException) as context:
                    plugin.change_password()
                
                self.assertEqual(expected_code, context.exception.codes[0]["code"])
                self.assertIn(expected_message, str(context.exception))

    @patch('elasticsearch_serviceaccount_token.Elasticsearch')
    def test_malformed_api_responses(self, mock_elasticsearch):
        """Test handling of malformed API responses."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        malformed_responses = [
            ({}, "missing_token_info"),  # Missing token field
            ({"token": {}}, "missing_token_info"),  # Empty token field (falsy)
            ({"token": {"name": "test"}}, "missing_token_value"),  # Missing value field
        ]
        
        for response, expected_code in malformed_responses:
            with self.subTest(response=response):
                mock_client.security.create_service_token.return_value = response
                plugin = self.create_plugin()
                
                with self.assertRaises(SaasException) as context:
                    plugin.change_password()
                
                self.assertEqual(expected_code, context.exception.codes[0]["code"])

    # ==================== Integration Tests ====================

    def test_plugin_configuration_integration(self):
        """Test plugin configuration retrieval and processing."""
        config_overrides = {
            'elasticsearch_url': 'https://es.example.com:9200',
            'api_key': 'custom_api_key',
            'namespace': 'custom',
            'service': 'my-service',
            'verify_ssl': 'True'
        }
        
        plugin = self.create_plugin(config_overrides, token_name='my-token')
        
        # Verify configuration retrieval
        self.assertEqual("https://es.example.com:9200", plugin.get_config("elasticsearch_url"))
        self.assertEqual("custom_api_key", plugin.get_config("api_key"))
        self.assertEqual("custom", plugin.get_config("namespace"))
        self.assertEqual("my-service", plugin.get_config("service"))
        self.assertEqual("True", plugin.get_config("verify_ssl"))
        self.assertTrue(plugin.verify_ssl)
        
        # Verify token name retrieval from user fields
        token_name = plugin._get_token_name()
        self.assertEqual("my-token", token_name)

    def test_rollback_behavior(self):
        """Test rollback behavior (should do nothing gracefully)."""
        plugin = self.create_plugin()
        # Should not raise any exception
        plugin.rollback_password()
        
    def test_token_name_required_error(self):
        """Test error when token_name is not provided in user fields."""
        plugin = self.create_plugin(token_name=None)  # No token name in user fields
        
        with self.assertRaises(SaasException) as context:
            plugin._get_token_name()
        
        self.assertEqual("token_name_required", context.exception.codes[0]["code"])
        self.assertIn("Token name is required", str(context.exception))

    # ==================== Edge Cases ====================

    def test_ssl_context_creation_with_invalid_cert(self):
        """Test SSL context creation with invalid certificate content."""
        # Should raise SaasException for invalid certificate content
        with self.assertRaises(SaasException) as context:
            SaasPlugin.create_ssl_context(cert_content="invalid-cert-content", verify_ssl=True)
        
        self.assertEqual("invalid_ssl_cert", context.exception.codes[0]["code"])
        self.assertIn("Invalid SSL certificate", str(context.exception))


if __name__ == '__main__':
    unittest.main()
