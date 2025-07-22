from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from integrations.elasticsearch.elasticsearch_serviceaccount_token import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from elasticsearch.exceptions import ConflictError, NotFoundError, AuthenticationException
from plugin_dev.test_base import MockRecord
from typing import Optional


class ElasticsearchServiceAccountTokenTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None, 
               elasticsearch_url: str = "https://localhost:9200",
               api_key: str = "test_api_key",
               namespace: str = "elastic",
               service: str = "fleet-server",
               token_name: str = "test-token",
               verify_ssl: str = "False"):

        user = SaasUser(
            username=Secret("test-user"),
            new_password=Secret("dummy-password-not-used"),  # Required by framework
            prior_password=prior_password or Secret("old-dummy-password")
        )

        config_record = MockRecord(
            custom=[
                {'type': 'url', 'label': 'Elasticsearch URL', 'value': [elasticsearch_url]},
                {'type': 'secret', 'label': 'API Key', 'value': [api_key]},
                {'type': 'text', 'label': 'Service Account Namespace', 'value': [namespace]},
                {'type': 'text', 'label': 'Service Account Service', 'value': [service]},
                {'type': 'text', 'label': 'Token Name', 'value': [token_name]},
                {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """
        Check if requirement returns the correct module.
        """
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("elasticsearch", req_list[0])

    def test_config_schema(self):
        """
        Test the configuration schema.
        """
        schema = SaasPlugin.config_schema()
        self.assertEqual(7, len(schema))  # Updated to include token_name and ssl_content
        
        # Check required fields
        required_fields = [item for item in schema if item.required]
        self.assertEqual(5, len(required_fields))  # Updated count
        
        # Check field IDs
        field_ids = [item.id for item in schema]
        expected_ids = ["elasticsearch_url", "api_key", "namespace", "service", "token_name", "verify_ssl", "ssl_content"]
        self.assertEqual(set(expected_ids), set(field_ids))

    def test_can_rollback(self):
        """
        Test that rollback is not supported.
        """
        plugin = self.plugin()
        self.assertFalse(plugin.can_rollback)

    def test_url_validation(self):
        """
        Test URL validation.
        """
        plugin = self.plugin()
        
        # Valid URLs should not raise
        plugin._validate_url("https://localhost:9200")
        plugin._validate_url("http://elasticsearch.example.com:9200")
        
        # Invalid URLs should raise
        with self.assertRaises(SaasException) as context:
            plugin._validate_url("not-a-url")
        self.assertEqual(context.exception.code, "invalid_url")
        
        with self.assertRaises(SaasException) as context:
            plugin._validate_url("ftp://example.com")
        self.assertEqual(context.exception.code, "invalid_url")

    def test_token_name_validation(self):
        """
        Test token name validation.
        """
        plugin = self.plugin()
        
        # Valid token names should not raise
        plugin._validate_token_name("valid-token")
        plugin._validate_token_name("Token123")
        plugin._validate_token_name("my_token")
        
        # Invalid token names should raise
        with self.assertRaises(SaasException) as context:
            plugin._validate_token_name("_invalid-name")
        self.assertEqual(context.exception.code, "invalid_token_name")
        
        with self.assertRaises(SaasException) as context:
            plugin._validate_token_name("invalid@name")
        self.assertEqual(context.exception.code, "invalid_token_name")
        
        with self.assertRaises(SaasException) as context:
            plugin._validate_token_name("a" * 257)  # Too long
        self.assertEqual(context.exception.code, "invalid_token_name")

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_client_initialization(self, mock_elasticsearch):
        """
        Test that the Elasticsearch client is properly initialized.
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        
        plugin = self.plugin()
        client = plugin.client
        
        # Verify client was created with correct parameters
        mock_elasticsearch.assert_called_once_with(
            hosts=["https://localhost:9200"],
            api_key="test_api_key",
            verify_certs=False,  # Default is False
            request_timeout=30,
            retry_on_timeout=True,
            max_retries=3,
            ssl_context=None
        )
        
        # Verify ping was called
        mock_client.ping.assert_called_once()

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_client_connection_failure(self, mock_elasticsearch):
        """
        Test handling of client connection failures.
        """
        mock_elasticsearch.side_effect = Exception("Connection failed")
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertEqual(context.exception.code, "elasticsearch_connection_error")
        self.assertIn("Connection failed", str(context.exception))

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_successful_token_creation(self, mock_elasticsearch):
        """
        Test successful service account token creation.
        """
        # Mock successful response
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.security.create_service_token.return_value = {
            "created": True,
            "token": {
                "name": "test-token",
                "value": "AAEAAWVsYXN0aWM...test-token-value"
            }
        }
        
        plugin = self.plugin()
        plugin.change_password()
        
        # Verify the API was called correctly
        mock_client.security.create_service_token.assert_called_once_with(
            namespace="elastic",
            service="fleet-server",
            name="test-token"
        )
        
        # Verify return fields were added
        self.assertEqual(3, len(plugin.return_fields))  # Updated count
        
        # Check that the token value is returned
        token_field = next((f for f in plugin.return_fields if f.label == "Service Account Token"), None)
        self.assertIsNotNone(token_field)
        self.assertEqual("AAEAAWVsYXN0aWM...test-token-value", token_field.value.value)

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_token_already_exists(self, mock_elasticsearch):
        """
        Test handling when token already exists.
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.security.create_service_token.side_effect = ConflictError("Conflict", {}, {})
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual(context.exception.code, "token_already_exists")
        self.assertIn("already exists", str(context.exception))

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_service_account_not_found(self, mock_elasticsearch):
        """
        Test handling when service account doesn't exist.
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.security.create_service_token.side_effect = NotFoundError("Not Found", {}, {})
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual(context.exception.code, "service_account_not_found")
        self.assertIn("not found", str(context.exception))

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_authentication_failed(self, mock_elasticsearch):
        """
        Test handling authentication failures.
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.security.create_service_token.side_effect = AuthenticationException("Auth Failed", {}, {})
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual(context.exception.code, "authentication_failed")
        self.assertIn("Authentication failed", str(context.exception))

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_missing_token_value_in_response(self, mock_elasticsearch):
        """
        Test handling when token value is missing from response.
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.security.create_service_token.return_value = {
            "created": True,
            "token": {
                "name": "test-token"
                # Missing "value" field
            }
        }
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual(context.exception.code, "missing_token_value")

    @patch('integrations.elasticsearch.elasticsearch_serviceaccount_token.Elasticsearch')
    def test_missing_token_info_in_response(self, mock_elasticsearch):
        """
        Test handling when token info is missing from response.
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.security.create_service_token.return_value = {
            "created": True
            # Missing "token" field
        }
        
        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertEqual(context.exception.code, "missing_token_info")

    def test_rollback_password(self):
        """
        Test rollback behavior (should do nothing).
        """
        plugin = self.plugin()
        # Should not raise any exception
        plugin.rollback_password()

    def test_different_configurations(self):
        """
        Test plugin with different configuration values.
        """
        plugin = self.plugin(
            elasticsearch_url="https://es.example.com:9200",
            api_key="custom_api_key",
            namespace="custom",
            service="my-service",
            token_name="my-token",
            verify_ssl="True"
        )
        
        self.assertEqual("https://es.example.com:9200", plugin.get_config("elasticsearch_url"))
        self.assertEqual("custom_api_key", plugin.get_config("api_key"))
        self.assertEqual("custom", plugin.get_config("namespace"))
        self.assertEqual("my-service", plugin.get_config("service"))
        self.assertEqual("my-token", plugin.get_config("token_name"))
        self.assertEqual("True", plugin.get_config("verify_ssl"))
        self.assertTrue(plugin.verify_ssl)


if __name__ == '__main__':
    unittest.main()
