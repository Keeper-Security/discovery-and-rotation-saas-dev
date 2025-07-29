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
from typing import Optional, Dict, Any
import base64

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from elasticsearch_api_key import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "elasticsearch_api_key", 
        os.path.join(os.path.dirname(__file__), "elasticsearch_api_key.py")
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


class ElasticsearchApiKeyTestUtils:
    """Utility methods for creating test data specific to the API Key plugin."""

    @staticmethod
    def create_api_key_config_fields(elasticsearch_url: str = DEFAULT_ELASTICSEARCH_URL,
                                   username: str = "admin",
                                   password: str = "admin_password",
                                   verify_ssl: str = "False",
                                   ssl_content: str = "") -> list:
        """Create config fields for the API Key plugin."""
        return [
            {'type': 'url', 'label': 'Elasticsearch URL', 'value': [elasticsearch_url]},
            {'type': 'text', 'label': 'Admin Username', 'value': [username]},
            {'type': 'secret', 'label': 'Admin Password', 'value': [password]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]

    @staticmethod
    def create_api_key_field(encoded_api_key: str) -> Field:
        """Create an api_key_encoded field for user fields."""
        return Field(
            label="api_key_encoded",
            type="secret",
            values=[encoded_api_key]
        )

    @staticmethod
    def create_encoded_api_key(api_key_id: str = "test-id", api_key_value: str = "test-key") -> str:
        """Create a base64 encoded API key for testing."""
        api_key_string = f"{api_key_id}:{api_key_value}"
        return base64.b64encode(api_key_string.encode('utf-8')).decode('utf-8')


class ElasticsearchApiKeyTest(ElasticsearchTestBase):
    """Test suite for Elasticsearch API Key SaaS plugin."""

    def setUp(self):
        """Set up test environment before each test."""
        super().setUp()
        
        # Default API key for testing (base64 of "test-id:test-key")
        self.test_api_key_encoded = ElasticsearchApiKeyTestUtils.create_encoded_api_key()

    def create_plugin(self, config_overrides: Optional[Dict[str, str]] = None, 
                     prior_password: Optional[Secret] = None,
                     api_key: Optional[str] = None) -> SaasPlugin:
        """
        Create a SaasPlugin instance with test configuration.
        
        Args:
            config_overrides: Override default config values
            prior_password: Prior password for user
            api_key: API key for user fields
            
        Returns:
            Configured SaasPlugin instance
        """
        # Create user fields with api_key_encoded
        user_fields = []
        if api_key is not None:
            user_fields.append(ElasticsearchApiKeyTestUtils.create_api_key_field(api_key))
        elif api_key != "NONE":  # Use default unless explicitly set to "NONE"
            user_fields.append(ElasticsearchApiKeyTestUtils.create_api_key_field(self.test_api_key_encoded))
        
        user = self.create_user(
            username=DEFAULT_USERNAME,
            new_password="dummy-password-not-used",
            prior_password=prior_password.value if prior_password else "old-dummy-password",
            fields=user_fields
        )

        # Create config with defaults and overrides
        elasticsearch_url = config_overrides.get('elasticsearch_url', DEFAULT_ELASTICSEARCH_URL) if config_overrides else DEFAULT_ELASTICSEARCH_URL
        username = config_overrides.get('username', 'admin') if config_overrides else 'admin'
        password = config_overrides.get('password', 'admin_password') if config_overrides else 'admin_password'
        verify_ssl = config_overrides.get('verify_ssl', 'False') if config_overrides else 'False'
        ssl_content = config_overrides.get('ssl_content', '') if config_overrides else ''

        config_fields = ElasticsearchApiKeyTestUtils.create_api_key_config_fields(
            elasticsearch_url=elasticsearch_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            ssl_content=ssl_content
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)



    # ==================== Basic Plugin Tests ====================

    def test_plugin_metadata(self):
        """Test plugin basic metadata and requirements."""
        # Test requirements
        req_list = SaasPlugin.requirements()
        self.assertEqual(["elasticsearch"], req_list)
        
        # Test metadata
        self.assertEqual("Elasticsearch API Key", SaasPlugin.name)
        self.assertEqual("Keeper Security", SaasPlugin.author)
        self.assertEqual("README.md", SaasPlugin.readme)
        self.assertFalse(self.create_plugin().can_rollback)

    def test_config_schema_structure(self):
        """Test configuration schema structure and field definitions."""
        schema = SaasPlugin.config_schema()
        
        # Verify schema size and required fields
        self.assertEqual(5, len(schema))
        required_fields = [item for item in schema if item.required]
        self.assertEqual(3, len(required_fields))
        
        # Verify all expected field IDs are present
        field_ids = {item.id for item in schema}
        expected_ids = {"elasticsearch_url", "username", "password", "verify_ssl", "ssl_content"}
        self.assertEqual(expected_ids, field_ids)
        
        # Verify specific field configurations
        password_field = next(item for item in schema if item.id == "password")
        self.assertTrue(password_field.is_secret)
        self.assertTrue(password_field.required)

    # ==================== Validation Tests ====================

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

    def test_api_key_extraction_success(self):
        """Test successful API key extraction from user fields."""
        plugin = self.create_plugin()
        api_key = plugin._get_api_key_from_user_fields()
        self.assertEqual(self.test_api_key_encoded, api_key)

    def test_api_key_extraction_missing(self):
        """Test API key extraction when no API key is provided."""
        # Create user with no fields at all
        user = SaasUser(
            username=Secret("test-user"),
            new_password=Secret("dummy-password-not-used"),
            prior_password=Secret("old-dummy-password"),
            fields=[]  # Empty fields list
        )

        config_record = MockRecord(
            custom=[
                {'type': 'url', 'label': 'Elasticsearch URL', 'value': ['https://localhost:9200']},
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
                {'type': 'text', 'label': 'Verify SSL', 'value': ['False']},
                {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': ['']},
            ]
        )

        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin._get_api_key_from_user_fields()
        self.assertEqual("api_key_required", context.exception.codes[0]["code"])

    def test_api_key_id_extraction_success(self):
        """Test successful API key ID extraction from encoded format."""
        plugin = self.create_plugin()
        api_key_id = plugin._extract_api_key_id(self.test_api_key_encoded)
        self.assertEqual("test-id", api_key_id)

    def test_api_key_id_extraction_invalid_format(self):
        """Test API key ID extraction with invalid format."""
        plugin = self.create_plugin()
        
        invalid_keys = [
            "not-base64",
            base64.b64encode(b"no-colon-here").decode('utf-8'),  # Valid base64 but no colon
            "",
        ]
        
        for invalid_key in invalid_keys:
            with self.subTest(key=invalid_key):
                with self.assertRaises(SaasException) as context:
                    plugin._extract_api_key_id(invalid_key)
                self.assertEqual("invalid_api_key_format", context.exception.codes[0]["code"])

    # ==================== SSL Context Tests ====================

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

    # ==================== Client Connection Tests ====================

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_client_initialization_success(self, mock_elasticsearch):
        """Test successful Elasticsearch client initialization."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        plugin = self.create_plugin()
        client = plugin.client
        
        mock_elasticsearch.assert_called_once()
        mock_client.ping.assert_called_once()
        self.assertEqual(mock_client, client)

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_client_initialization_auth_failure(self, mock_elasticsearch):
        """Test client initialization with authentication failure."""
        mock_elasticsearch.side_effect = Exception("Auth failed")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertEqual("elasticsearch_connection_error", context.exception.codes[0]["code"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_client_initialization_connection_failure(self, mock_elasticsearch):
        """Test client initialization with connection failure."""
        mock_elasticsearch.side_effect = Exception("Connection failed")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertEqual("elasticsearch_connection_error", context.exception.codes[0]["code"])

    # ==================== API Key Info Tests ====================

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_fetch_api_key_info_success(self, mock_elasticsearch):
        """Test successful API key info fetching."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.get_api_key.return_value = {
            "api_keys": [{
                "id": "test-id",
                "name": "test-key",
                "role_descriptors": {"test-role": {"cluster": ["all"]}},
                "expiration": 1234567890000
            }]
        }
        
        plugin = self.create_plugin()
        result = plugin._fetch_api_key_info("test-id")
        
        mock_client.security.get_api_key.assert_called_once_with(id="test-id")
        self.assertEqual("test-id", result["id"])
        self.assertEqual("test-key", result["name"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_fetch_api_key_info_not_found(self, mock_elasticsearch):
        """Test API key info fetching when key not found."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.get_api_key.side_effect = Exception("Not found")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._fetch_api_key_info("nonexistent-id")
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_fetch_api_key_info_empty_response(self, mock_elasticsearch):
        """Test API key info fetching with empty response."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.get_api_key.return_value = {"api_keys": []}
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._fetch_api_key_info("test-id")
        
        # The method raises SaasException directly, but since there's no SaasException re-raise clause,
        # it gets caught by the generic Exception handler and returns "elasticsearch_error"
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    # ==================== Role Descriptor Tests ====================

    def test_clean_role_descriptors_success(self):
        """Test successful role descriptor cleaning."""
        plugin = self.create_plugin()
        
        role_descriptors = {
            "test-role": {
                "cluster": ["all"],
                "indices": [{"names": ["*"], "privileges": ["read"]}],
                "extra_field": "should_be_removed"
            },
            "another-role": {
                "applications": [{"application": "app", "privileges": ["read"]}],
                "run_as": ["user1"]
            }
        }
        
        result = plugin._clean_role_descriptors(role_descriptors)
        
        self.assertIsNotNone(result)
        self.assertIn("test-role", result)
        self.assertIn("another-role", result)
        self.assertNotIn("extra_field", result["test-role"])
        self.assertIn("cluster", result["test-role"])
        self.assertIn("indices", result["test-role"])

    def test_clean_role_descriptors_none(self):
        """Test role descriptor cleaning with None input."""
        plugin = self.create_plugin()
        result = plugin._clean_role_descriptors(None)
        self.assertIsNone(result)

    def test_clean_role_descriptors_invalid_format(self):
        """Test role descriptor cleaning with invalid format."""
        plugin = self.create_plugin()
        
        invalid_descriptors = {
            "invalid-role": "not-a-dict",
            "empty-role": {},
            "valid-role": {"cluster": ["all"]}
        }
        
        result = plugin._clean_role_descriptors(invalid_descriptors)
        
        # Should only contain the valid role
        self.assertIsNotNone(result)
        self.assertEqual(1, len(result))
        self.assertIn("valid-role", result)

    # ==================== API Key Creation Tests ====================

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_create_api_key_success(self, mock_elasticsearch):
        """Test successful API key creation."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.create_api_key.return_value = {
            "id": "new-id",
            "name": "new-key",
            "api_key": "new-key-value",
            "encoded": "new-encoded-value"
        }
        
        plugin = self.create_plugin()
        role_descriptors = {"test-role": {"cluster": ["all"]}}
        
        result = plugin._create_new_api_key(
            name="test-key",
            role_descriptors=role_descriptors,
            expiration="1d"
        )
        
        mock_client.security.create_api_key.assert_called_once()
        call_args = mock_client.security.create_api_key.call_args[1]
        self.assertEqual("test-key", call_args["name"])
        self.assertIn("role_descriptors", call_args)
        self.assertEqual("1d", call_args["expiration"])
        
        self.assertEqual("new-id", result["id"])
        self.assertEqual("new-key", result["name"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_create_api_key_bad_request(self, mock_elasticsearch):
        """Test API key creation with bad request error."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.create_api_key.side_effect = Exception("Bad request")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._create_new_api_key("test-key")
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_create_api_key_auth_failure(self, mock_elasticsearch):
        """Test API key creation with authentication failure."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.create_api_key.side_effect = Exception("Auth failed")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._create_new_api_key("test-key")
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_create_api_key_authorization_failure(self, mock_elasticsearch):
        """Test API key creation with authorization failure."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.create_api_key.side_effect = Exception("Authorization failed")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._create_new_api_key("test-key")
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    # ==================== API Key Invalidation Tests ====================

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_invalidate_api_key_success(self, mock_elasticsearch):
        """Test successful API key invalidation."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        plugin = self.create_plugin()
        plugin._invalidate_api_key("test-id")
        
        mock_client.security.invalidate_api_key.assert_called_once_with(ids=["test-id"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_invalidate_api_key_not_found(self, mock_elasticsearch):
        """Test API key invalidation when key not found."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.invalidate_api_key.side_effect = Exception("Not found")
        
        plugin = self.create_plugin()
        
        # Since the exception falls through to generic handler, it will raise SaasException
        with self.assertRaises(SaasException) as context:
            plugin._invalidate_api_key("test-id")
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])
        mock_client.security.invalidate_api_key.assert_called_once_with(ids=["test-id"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_invalidate_api_key_auth_failure(self, mock_elasticsearch):
        """Test API key invalidation with authentication failure."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.invalidate_api_key.side_effect = Exception("Auth failed")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin._invalidate_api_key("test-id")
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    # ==================== Return Fields Tests ====================

    def test_add_return_fields_complete(self):
        """Test adding return fields with complete API key response."""
        plugin = self.create_plugin()
        
        api_key_response = {
            "name": "test-key",
            "encoded": "test-encoded-value"
        }
        
        plugin._add_return_fields(api_key_response)
        
        self.assertEqual(2, len(plugin.return_fields))
        
        # Check that expected fields are present
        field_labels = {field.label for field in plugin.return_fields}
        expected_labels = {"API Key Name", "api_key_encoded"}
        self.assertEqual(expected_labels, field_labels)

    def test_add_return_fields_partial(self):
        """Test adding return fields with partial API key response."""
        plugin = self.create_plugin()
        
        api_key_response = {
            "encoded": "test-encoded-value"
            # Missing name
        }
        
        plugin._add_return_fields(api_key_response)
        
        self.assertEqual(1, len(plugin.return_fields))
        field_labels = {field.label for field in plugin.return_fields}
        self.assertIn("api_key_encoded", field_labels)

    # ==================== Integration Tests ====================

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_change_password_success(self, mock_elasticsearch):
        """Test successful password change (API key rotation)."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        # Mock get_api_key response
        mock_client.security.get_api_key.return_value = {
            "api_keys": [{
                "id": "test-id",
                "name": "original-key",
                "role_descriptors": {"test-role": {"cluster": ["all"]}}
            }]
        }
        
        # Mock create_api_key response
        mock_client.security.create_api_key.return_value = {
            "id": "new-id",
            "name": "original-key",
            "api_key": "new-key-value",
            "encoded": "new-encoded-value"
        }
        
        plugin = self.create_plugin()
        plugin.change_password()
        
        # Verify the sequence of calls
        mock_client.security.get_api_key.assert_called_once_with(id="test-id")
        mock_client.security.create_api_key.assert_called_once()
        mock_client.security.invalidate_api_key.assert_called_once_with(ids=["test-id"])
        
        # Verify return fields were added
        self.assertGreater(len(plugin.return_fields), 0)

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_change_password_fetch_failure(self, mock_elasticsearch):
        """Test password change with API key fetch failure."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        mock_client.security.get_api_key.side_effect = Exception("Not found")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    @patch('elasticsearch_api_key.Elasticsearch')
    def test_change_password_create_failure(self, mock_elasticsearch):
        """Test password change with API key creation failure."""
        mock_client = self.create_mock_elasticsearch_client(mock_elasticsearch)
        
        # Mock successful get_api_key
        mock_client.security.get_api_key.return_value = {
            "api_keys": [{
                "id": "test-id",
                "name": "original-key",
                "role_descriptors": {"test-role": {"cluster": ["all"]}}
            }]
        }
        
        mock_client.security.create_api_key.side_effect = Exception("Bad request")
        
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        # The exception falls through to the generic handler and gets wrapped as "elasticsearch_error"
        self.assertEqual("elasticsearch_error", context.exception.codes[0]["code"])

    def test_change_password_no_api_key(self):
        """Test password change when no API key is provided."""
        # Create user with no fields at all
        user = SaasUser(
            username=Secret("test-user"),
            new_password=Secret("dummy-password-not-used"),
            prior_password=Secret("old-dummy-password"),
            fields=[]  # Empty fields list
        )

        config_record = MockRecord(
            custom=[
                {'type': 'url', 'label': 'Elasticsearch URL', 'value': ['https://localhost:9200']},
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
                {'type': 'text', 'label': 'Verify SSL', 'value': ['False']},
                {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': ['']},
            ]
        )

        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual("api_key_required", context.exception.codes[0]["code"])

    # ==================== Rollback Tests ====================

    def test_rollback_not_supported(self):
        """Test that rollback is not supported."""
        plugin = self.create_plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertEqual("rollback_not_supported", context.exception.codes[0]["code"])
        self.assertIn("not supported", str(context.exception))

    # ==================== Edge Cases ====================

    def test_verify_ssl_property(self):
        """Test verify_ssl property with different values."""
        # Test with "True" value
        config_record = MockRecord(
            custom=[
                {'type': 'url', 'label': 'Elasticsearch URL', 'value': ['https://localhost:9200']},
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
                {'type': 'text', 'label': 'Verify SSL', 'value': ['True']},
                {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': ['']},
            ]
        )
        user = SaasUser(
            username=Secret("test-user"),
            new_password=Secret("dummy-password-not-used"),
            prior_password=Secret("old-dummy-password"),
            fields=[Field(type="secret", label="api_key_encoded", values=[self.test_api_key_encoded])]
        )
        plugin = SaasPlugin(user=user, config_record=config_record)
        self.assertTrue(plugin.verify_ssl)

        # Test with "False" value  
        config_record.dict['custom'][3]['value'] = ['False']
        plugin = SaasPlugin(user=user, config_record=config_record)
        self.assertFalse(plugin.verify_ssl)

    def test_can_rollback_property(self):
        """Test can_rollback property states."""
        plugin = self.create_plugin()
        
        # Initially should be False
        self.assertFalse(plugin.can_rollback)
        
        # After setting API key info, should be True
        plugin._current_api_key_info = {"id": "test-id"}
        self.assertTrue(plugin.can_rollback)

    def test_build_api_key_request_variations(self):
        """Test API key request building with different parameters."""
        plugin = self.create_plugin()
        
        # Test with minimal parameters
        request = plugin._build_api_key_request("test-name", None, None)
        expected = {"name": "test-name"}
        self.assertEqual(expected, request)
        
        # Test with role descriptors
        role_descriptors = {"test-role": {"cluster": ["all"]}}
        request = plugin._build_api_key_request("test-name", role_descriptors, None)
        self.assertIn("role_descriptors", request)
        
        # Test with expiration
        request = plugin._build_api_key_request("test-name", None, "1d")
        self.assertIn("expiration", request)
        self.assertEqual("1d", request["expiration"])


if __name__ == '__main__':
    unittest.main() 