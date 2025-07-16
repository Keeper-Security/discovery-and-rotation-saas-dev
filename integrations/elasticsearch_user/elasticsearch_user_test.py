import unittest
from unittest.mock import Mock, patch, MagicMock
from kdnrm.saas_type import SaasUser, Secret
from kdnrm.exceptions import SaasException
from elasticsearch.exceptions import AuthenticationException, NotFoundError, RequestError, ConnectionError
from integrations.elasticsearch_user.elasticsearch_user import SaasPlugin


class TestElasticsearchUserPlugin(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Mock user with username and passwords
        self.mock_user = Mock(spec=SaasUser)
        self.mock_user.username = Mock()
        self.mock_user.username.value = "testuser"
        self.mock_user.new_password = Secret("new_test_password_123")
        self.mock_user.prior_password = Secret("old_test_password_456")

        # Mock config record
        self.mock_config_record = Mock()

        # Mock configuration values
        self.config_values = {
            "admin_username": "admin",
            "admin_password": "admin_password",
            "elasticsearch_url": "https://localhost:9200",
            "verify_ssl": "True"
        }

    def _create_plugin(self, user=None, config_record=None, force_fail=False):
        """Helper method to create plugin instance."""
        user = user or self.mock_user
        config_record = config_record or self.mock_config_record
        
        plugin = SaasPlugin(user, config_record, force_fail=force_fail)
        
        # Mock get_config method
        plugin.get_config = Mock(side_effect=lambda key: self.config_values.get(key))
        
        return plugin

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_client_creation_success(self, mock_elasticsearch_class):
        """Test successful Elasticsearch client creation."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        client = plugin.client
        
        # Verify
        self.assertEqual(client, mock_client)
        mock_elasticsearch_class.assert_called_once()
        mock_client.ping.assert_called_once()

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_client_creation_connection_failure(self, mock_elasticsearch_class):
        """Test client creation with connection failure."""
        # Setup
        mock_elasticsearch_class.side_effect = ConnectionError("Connection failed")
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertIn("Connection failed", str(context.exception))

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_client_creation_authentication_failure(self, mock_elasticsearch_class):
        """Test client creation with authentication failure."""
        # Setup
        mock_elasticsearch_class.side_effect = AuthenticationException("Authentication failed")
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertIn("Authentication failed", str(context.exception))

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_client_creation_ping_failure(self, mock_elasticsearch_class):
        """Test client creation when ping fails."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = False
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            _ = plugin.client
        
        self.assertIn("Unable to connect", str(context.exception))

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_ssl_verification_disabled(self, mock_elasticsearch_class):
        """Test SSL verification disabled."""
        # Setup
        self.config_values["verify_ssl"] = "False"
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        _ = plugin.client
        
        # Verify SSL context and verify_certs parameters
        call_args = mock_elasticsearch_class.call_args
        self.assertIsNotNone(call_args[1]['ssl_context'])
        self.assertFalse(call_args[1]['verify_certs'])

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_can_rollback_success(self, mock_elasticsearch_class):
        """Test can_rollback property when user exists."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        result = plugin.can_rollback
        
        # Verify
        self.assertTrue(result)
        mock_client.security.get_user.assert_called_with(username="testuser")

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_can_rollback_user_not_found(self, mock_elasticsearch_class):
        """Test can_rollback property when user doesn't exist."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.side_effect = NotFoundError("User not found")
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        result = plugin.can_rollback
        
        # Verify
        self.assertFalse(result)

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_verify_user_exists_success(self, mock_elasticsearch_class):
        """Test user existence verification success."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        result = plugin._verify_user_exists()
        
        # Verify
        self.assertTrue(result)

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_verify_user_exists_not_found(self, mock_elasticsearch_class):
        """Test user existence verification when user not found."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.side_effect = NotFoundError("User not found")
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            plugin._verify_user_exists()
        
        self.assertIn("does not exist", str(context.exception))

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_change_password_success(self, mock_elasticsearch_class):
        """Test successful password change."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
        mock_client.security.change_password.return_value = {"acknowledged": True}
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        plugin.change_password()
        
        # Verify
        mock_client.security.get_user.assert_called_with(username="testuser")
        mock_client.security.change_password.assert_called_with(
            username="testuser",
            password="new_test_password_123"
        )

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_change_password_user_not_found(self, mock_elasticsearch_class):
        """Test password change when user doesn't exist."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.side_effect = NotFoundError("User not found")
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("does not exist", str(context.exception))

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_change_password_request_error(self, mock_elasticsearch_class):
        """Test password change with invalid request."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
        mock_client.security.change_password.side_effect = RequestError("Invalid request")
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("Invalid password change request", str(context.exception))

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_rollback_password_success(self, mock_elasticsearch_class):
        """Test successful password rollback."""
        # Setup
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
        mock_client.security.change_password.return_value = {"acknowledged": True}
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute
        plugin.rollback_password()
        
        # Verify
        mock_client.security.change_password.assert_called_with(
            username="testuser",
            password="old_test_password_456"
        )

    @patch('integrations.elasticsearch_user.elasticsearch_user.Elasticsearch')
    def test_rollback_password_no_prior_password(self, mock_elasticsearch_class):
        """Test password rollback when no prior password exists."""
        # Setup
        self.mock_user.prior_password = None
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_elasticsearch_class.return_value = mock_client
        
        plugin = self._create_plugin()
        
        # Execute & Verify
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("No prior password available", str(context.exception))

    def test_config_schema(self):
        """Test configuration schema."""
        schema = SaasPlugin.config_schema()
        
        # Verify required fields
        field_ids = [item.id for item in schema]
        expected_fields = ["admin_username", "admin_password", "elasticsearch_url", "verify_ssl"]
        
        for field in expected_fields:
            self.assertIn(field, field_ids)
        
        # Verify admin_password is secret
        admin_password_field = next(item for item in schema if item.id == "admin_password")
        self.assertTrue(admin_password_field.is_secret)
        
        # Verify URL field type
        url_field = next(item for item in schema if item.id == "elasticsearch_url")
        self.assertEqual(url_field.type, "url")

    def test_requirements(self):
        """Test plugin requirements."""
        requirements = SaasPlugin.requirements()
        self.assertIn("elasticsearch", requirements)

    def test_plugin_metadata(self):
        """Test plugin metadata."""
        self.assertEqual(SaasPlugin.name, "Elasticsearch User")
        self.assertEqual(SaasPlugin.summary, "Change a user password in Elasticsearch.")
        self.assertEqual(SaasPlugin.readme, "README.md")
        self.assertEqual(SaasPlugin.author, "Keeper Security")
        self.assertEqual(SaasPlugin.email, "pam@keepersecurity.com")


if __name__ == '__main__':
    unittest.main() 