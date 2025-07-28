from __future__ import annotations
import unittest
from unittest.mock import MagicMock
from typing import Optional, Dict, Any, List
import base64

from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, Field
from plugin_dev.test_base import MockRecord


class ElasticsearchTestBase(unittest.TestCase):
    """Base test class for Elasticsearch plugin tests with common functionality."""

    def setUp(self):
        """Set up test environment before each test."""
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    def create_mock_elasticsearch_client(self, mock_elasticsearch: MagicMock) -> MagicMock:
        """
        Create and configure a mock Elasticsearch client.
        
        Args:
            mock_elasticsearch: The mocked Elasticsearch class
            
        Returns:
            Configured mock client instance
        """
        mock_client = MagicMock()
        mock_elasticsearch.return_value = mock_client
        mock_client.ping.return_value = True
        return mock_client

    def create_user(self, 
                   username: str = "test-user",
                   new_password: str = "NewPassword123!",
                   prior_password: Optional[str] = None,
                   fields: Optional[List[Field]] = None) -> SaasUser:
        """
        Create a SaasUser instance for testing.
        
        Args:
            username: Username for the user
            new_password: New password for the user
            prior_password: Prior password for the user
            fields: Additional fields for the user
            
        Returns:
            Configured SaasUser instance
        """
        return SaasUser(
            username=Secret(username),
            new_password=Secret(new_password),
            prior_password=Secret(prior_password) if prior_password else None,
            fields=fields or []
        )

    def create_config_record(self, config_fields: List[Dict[str, Any]]) -> MockRecord:
        """
        Create a MockRecord for configuration.
        
        Args:
            config_fields: List of field dictionaries for configuration
            
        Returns:
            MockRecord instance
        """
        return MockRecord(custom=config_fields)

    def create_field(self, field_type: str, label: str, value: Any, is_secret: bool = False) -> Dict[str, Any]:
        """
        Create a configuration field dictionary.
        
        Args:
            field_type: Type of the field (text, secret, url, multiline)
            label: Label for the field
            value: Value for the field
            is_secret: Whether the field is secret
            
        Returns:
            Field dictionary
        """
        field_dict = {
            'type': field_type,
            'label': label,
            'value': [value]
        }
        if is_secret:
            field_dict['is_secret'] = True
        return field_dict


class ElasticsearchUsersTestUtils:
    """Utility functions specific to Elasticsearch Users plugin tests."""

    @staticmethod
    def create_users_config_fields(elasticsearch_url: str = "https://localhost:9200",
                                  api_key: str = "test_api_key_12345",
                                  verify_ssl: str = "True",
                                  ssl_content: str = "") -> List[Dict[str, Any]]:
        """Create configuration fields for Users plugin."""
        return [
            {'type': 'secret', 'label': 'API Key', 'value': [api_key]},
            {'type': 'url', 'label': 'Elasticsearch URL', 'value': [elasticsearch_url]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]


class ElasticsearchApiKeyTestUtils:
    """Utility functions specific to Elasticsearch API Key plugin tests."""

    @staticmethod
    def create_api_key_config_fields(elasticsearch_url: str = "https://localhost:9200",
                                    username: str = "admin",
                                    password: str = "admin_password",
                                    verify_ssl: str = "False",
                                    ssl_content: str = "") -> List[Dict[str, Any]]:
        """Create configuration fields for API Key plugin."""
        return [
            {'type': 'url', 'label': 'Elasticsearch URL', 'value': [elasticsearch_url]},
            {'type': 'text', 'label': 'Admin Username', 'value': [username]},
            {'type': 'secret', 'label': 'Admin Password', 'value': [password]},
            {'type': 'text', 'label': 'Verify SSL', 'value': [verify_ssl]},
            {'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [ssl_content]},
        ]

    @staticmethod
    def create_encoded_api_key(api_key_id: str = "test-id", api_key: str = "test-key") -> str:
        """Create a base64 encoded API key for testing."""
        return base64.b64encode(f"{api_key_id}:{api_key}".encode('utf-8')).decode('utf-8')

    @staticmethod
    def create_api_key_field(encoded_api_key: str) -> Field:
        """Create an API key field for user."""
        return Field(
            type="secret",
            label="api_key_encoded",
            values=[encoded_api_key]
        )


class ElasticsearchServiceAccountTestUtils:
    """Utility functions specific to Elasticsearch Service Account plugin tests."""

    @staticmethod
    def create_service_account_config_fields(elasticsearch_url: str = "https://localhost:9200",
                                           api_key: str = "test_api_key",
                                           namespace: str = "elastic",
                                           service: str = "fleet-server",
                                           verify_ssl: str = "False",
                                           ssl_content: str = "") -> List[Dict[str, Any]]:
        """Create configuration fields for Service Account plugin."""
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
        """Create a token name field for user."""
        return Field(
            type="text",
            label="token_name",
            values=[token_name]
        )


# Common test data
DEFAULT_ELASTICSEARCH_URL = "https://localhost:9200"
DEFAULT_SSL_CERT = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
DEFAULT_USERNAME = "test-user"
DEFAULT_NEW_PASSWORD = "NewPassword123!"
DEFAULT_PRIOR_PASSWORD = "OldPassword123!" 