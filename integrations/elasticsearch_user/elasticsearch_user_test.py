from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from plugin_dev.test_base import MockRecord
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from elasticsearch_user import SaasPlugin
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from typing import Optional


class ElasticsearchUserPluginTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    def plugin(self,
               prior_password: Optional[Secret] = None,
               field_values: Optional[dict] = None,
               username: Optional[Secret] = None):

        if username is None:
            username = Secret("testuser")

        user = SaasUser(
            username=username,
            new_password=Secret("NewPassword123!"),
            prior_password=prior_password
        )

        if field_values is None:
            field_values = {
                "API Key": "test_api_key_12345",
                "Elasticsearch URL": "https://localhost:9200",
                "Verify SSL": "True"
            }

        config_record = MockRecord(
            custom=[
                {'type': 'secret', 'label': 'API Key', 'value': [field_values.get("API Key")]},
                {'type': 'url', 'label': 'Elasticsearch URL', 'value': [field_values.get("Elasticsearch URL")]},
                {'type': 'text', 'label': 'Verify SSL', 'value': [field_values.get("Verify SSL")]},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual(req_list[0], "elasticsearch")

    def test_change_password_success_https(self):
        """Test successful password change with HTTPS connection."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

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

    def test_change_password_success_http(self):
        """Test successful password change with HTTP connection (no SSL)."""
        field_values = {
            "API Key": "test_api_key_12345",
            "Elasticsearch URL": "http://localhost:9200",
            "Verify SSL": "True"
        }

        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify SSL settings were not applied for HTTP
            call_args = mock_client_class.call_args[1]
            self.assertNotIn('ssl_context', call_args)
            self.assertNotIn('verify_certs', call_args)

    def test_change_password_success_ssl_disabled(self):
        """Test successful password change with SSL verification disabled."""
        field_values = {
            "API Key": "test_api_key_12345",
            "Elasticsearch URL": "https://localhost:9200",
            "Verify SSL": "False"
        }

        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify SSL context was configured for self-signed certificates
            call_args = mock_client_class.call_args[1]
            self.assertIn('ssl_context', call_args)
            self.assertFalse(call_args['verify_certs'])

    def test_change_password_fail_user_not_found(self):
        """Test password change when user doesn't exist."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
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

    def test_change_password_fail_authorization_error(self):
        """Test password change with authorization failure."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.side_effect = Exception("Forbidden")
            mock_client_class.return_value = mock_client

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Failed to verify user existence", str(err))

    def test_change_password_fail_request_error(self):
        """Test password change with invalid request."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.side_effect = Exception("Invalid request")
            mock_client_class.return_value = mock_client

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Failed to change password", str(err))

    def test_change_password_fail_connection_error(self):
        """Test password change with connection failure."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client_class.side_effect = ESConnectionError("Connection failed")

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Connection failed", str(err))

    def test_change_password_fail_authentication_error(self):
        """Test password change with authentication failure."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client_class.side_effect = Exception("Authentication failed")

            plugin = self.plugin()

            try:
                plugin.change_password()
                self.fail("Should have failed")
            except Exception as err:
                self.assertIn("Failed to create Elasticsearch client", str(err))

    def test_change_password_fail_ping_failure(self):
        """Test password change when ping fails."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
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
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client_class.return_value = mock_client

            plugin = self.plugin()
            plugin._verify_user_exists()
            
            self.assertTrue(plugin.can_rollback)

    def test_rollback_success(self):
        """Test successful password rollback."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
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
        expected_fields = ["api_key", "elasticsearch_url", "verify_ssl"]
        
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

    def test_plugin_metadata(self):
        """Test plugin metadata."""
        self.assertEqual(SaasPlugin.name, "Elasticsearch User")
        self.assertEqual(SaasPlugin.summary, "Change a user password in Elasticsearch.")
        self.assertEqual(SaasPlugin.readme, "README.md")
        self.assertEqual(SaasPlugin.author, "Keeper Security")
        self.assertEqual(SaasPlugin.email, "pam@keepersecurity.com")

    def test_client_creation_caching(self):
        """Test that Elasticsearch client is cached."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
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

    def test_verify_user_exists_sets_rollback_flag(self):
        """Test that _verify_user_exists sets the rollback flag."""
        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client_class.return_value = mock_client

            plugin = self.plugin()
            
            # Initially False
            self.assertFalse(plugin.can_rollback)
            
            # After verification, should be True
            plugin._verify_user_exists()
            self.assertTrue(plugin.can_rollback)

    def test_empty_api_key_handling(self):
        """Test behavior when API key is empty or None."""
        field_values = {
            "API Key": "",  # Empty API key
            "Elasticsearch URL": "http://localhost:9200",
            "Verify SSL": "True"
        }

        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

            plugin = self.plugin(field_values=field_values)
            plugin.change_password()

            # Verify client was created (empty/missing API key becomes None)
            call_args = mock_client_class.call_args[1]
            self.assertIsNone(call_args['api_key'])


if __name__ == '__main__':
    unittest.main()
