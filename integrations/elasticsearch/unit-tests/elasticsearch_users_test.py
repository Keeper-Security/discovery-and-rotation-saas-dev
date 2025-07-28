from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from plugin_dev.test_base import MockRecord
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
try:
    # Try relative import first (when run as package)
    from ..elasticsearch_users.elasticsearch_users import SaasPlugin
except ImportError:
    # Fall back to absolute import with path manipulation
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from elasticsearch_users.elasticsearch_users import SaasPlugin
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
                "Verify SSL": "True",
                "SSL Certificate Content": ""
            }

        custom_fields = []
        if "API Key" in field_values:
            custom_fields.append({'type': 'secret', 'label': 'API Key', 'value': [field_values.get("API Key")]})
        if "Elasticsearch URL" in field_values:
            custom_fields.append({'type': 'url', 'label': 'Elasticsearch URL', 'value': [field_values.get("Elasticsearch URL")]})
        if "Verify SSL" in field_values:
            custom_fields.append({'type': 'text', 'label': 'Verify SSL', 'value': [field_values.get("Verify SSL")]})
        if "SSL Certificate Content" in field_values:
            custom_fields.append({'type': 'multiline', 'label': 'SSL Certificate Content', 'value': [field_values.get("SSL Certificate Content")]})

        config_record = MockRecord(custom=custom_fields)

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

    def test_change_password_success_ssl_disabled(self):
        """Test successful password change with SSL verification disabled."""
        field_values = {
            "API Key": "test_api_key_12345",
            "Elasticsearch URL": "https://localhost:9200",
            "Verify SSL": "False",
            "SSL Certificate Content": ""
        }

        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.security.get_user.return_value = {"testuser": {"enabled": True}}
            mock_client.security.change_password.return_value = {"acknowledged": True}
            mock_client_class.return_value = mock_client

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

        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
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

        with patch("elasticsearch_user.Elasticsearch") as mock_client_class:
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
        self.assertEqual(SaasPlugin.readme, "README_elasticsearch_user.md")
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
        field_values_none = {k: v for k, v in field_values.items() if k != "Verify SSL"}
        plugin = self.plugin(field_values=field_values_none)
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


if __name__ == '__main__':
    unittest.main()
