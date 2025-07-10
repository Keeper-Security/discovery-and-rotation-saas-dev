from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from servicenow_users import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from typing import Optional


class ServiceNowUsersTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None):
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [],
            'custom': [
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin_user']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
                {'type': 'text', 'label': 'Instance Name', 'value': ['dev12345']},
            ]
        }
        config_record.title = 'ServiceNow Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # Mock the get_custom_field_value method
        config_record.get_custom_field_value.side_effect = [
            "admin_user",
            "admin_password", 
            "dev12345"
        ]

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test that the requirements method returns the correct list of requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("pysnc", req_list[0])

    def test_config_schema(self):
        """Test that the config schema is correctly defined."""
        schema = SaasPlugin.config_schema()
        self.assertEqual(3, len(schema))
        
        # Check admin_username field
        admin_username = schema[0]
        self.assertEqual("admin_username", admin_username.id)
        self.assertTrue(admin_username.is_secret)
        self.assertTrue(admin_username.required)
        
        # Check admin_password field
        admin_password = schema[1]
        self.assertEqual("admin_password", admin_password.id)
        self.assertTrue(admin_password.is_secret)
        self.assertTrue(admin_password.required)
        
        # Check instance_name field
        instance_name = schema[2]
        self.assertEqual("instance_name", instance_name.id)
        self.assertFalse(instance_name.is_secret)
        self.assertTrue(instance_name.required)

    @patch('servicenow_users.ServiceNowClient')
    def test_client_property(self, mock_servicenow_client):
        """Test that the client property initializes ServiceNowClient correctly."""
        plugin = self.plugin()
        
        # Access the client property
        client = plugin.client
        
        # Verify ServiceNowClient was called with correct parameters
        mock_servicenow_client.assert_called_once_with(
            instance="dev12345",
            auth=("admin_user", "admin_password")
        )

    @patch('servicenow_users.ServiceNowClient')
    def test_user_sys_id_success(self, mock_servicenow_client):
        """Test successful retrieval of user sys_id."""
        plugin = self.plugin()
        
        # Mock GlideRecord
        mock_gr = MagicMock()
        mock_gr.get.return_value = True
        mock_gr.get_value.return_value = "sys_id_12345"
        
        mock_client_instance = MagicMock()
        mock_client_instance.GlideRecord.return_value = mock_gr
        mock_servicenow_client.return_value = mock_client_instance
        
        # Get user sys_id
        sys_id = plugin.user_sys_id
        
        # Verify the result
        self.assertEqual(sys_id, "sys_id_12345")
        mock_client_instance.GlideRecord.assert_called_once_with("sys_user")
        mock_gr.get.assert_called_once_with("user_name", "jdoe")

    @patch('servicenow_users.ServiceNowClient')
    def test_user_sys_id_not_found(self, mock_servicenow_client):
        """Test user not found scenario."""
        plugin = self.plugin()
        
        # Mock GlideRecord to return False (user not found)
        mock_gr = MagicMock()
        mock_gr.get.return_value = False
        
        mock_client_instance = MagicMock()
        mock_client_instance.GlideRecord.return_value = mock_gr
        mock_servicenow_client.return_value = mock_client_instance
        
        # Test exception is raised
        with self.assertRaises(SaasException) as ctx:
            _ = plugin.user_sys_id
        self.assertIn("not found in ServiceNow", str(ctx.exception))

    def test_can_rollback(self):
        """Test that can_rollback property returns True."""
        plugin = self.plugin()
        self.assertTrue(plugin.can_rollback)

    def test_build_user_api_url(self):
        """Test URL building method."""
        plugin = self.plugin()
        url = plugin._build_user_api_url("test_sys_id")
        expected_url = "https://dev12345.service-now.com/api/now/table/sys_user/test_sys_id"
        self.assertEqual(url, expected_url)

    @patch('servicenow_users.ServiceNowClient')
    def test_update_password_success(self, mock_servicenow_client):
        """Test successful password update."""
        plugin = self.plugin()
        
        # Mock the client and response
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        mock_session = MagicMock()
        mock_session.patch.return_value = mock_response
        
        mock_client_instance = MagicMock()
        mock_client_instance.session = mock_session
        
        # Mock GlideRecord for user_sys_id
        mock_gr = MagicMock()
        mock_gr.get.return_value = True
        mock_gr.get_value.return_value = "sys_id_12345"
        mock_client_instance.GlideRecord.return_value = mock_gr
        
        mock_servicenow_client.return_value = mock_client_instance
        
        # Test password update
        plugin.update_password(Secret("NewPassword123"))
        
        # Verify the patch call was made
        mock_session.patch.assert_called_once()
        call_args = mock_session.patch.call_args
        self.assertIn("https://dev12345.service-now.com/api/now/table/sys_user/sys_id_12345", call_args[0])

    @patch('servicenow_users.ServiceNowClient')
    def test_update_password_http_error(self, mock_servicenow_client):
        """Test password update with HTTP error."""
        plugin = self.plugin()
        
        # Mock the client and error response
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        
        mock_session = MagicMock()
        mock_session.patch.return_value = mock_response
        
        mock_client_instance = MagicMock()
        mock_client_instance.session = mock_session
        
        # Mock GlideRecord for user_sys_id
        mock_gr = MagicMock()
        mock_gr.get.return_value = True
        mock_gr.get_value.return_value = "sys_id_12345"
        mock_client_instance.GlideRecord.return_value = mock_gr
        
        mock_servicenow_client.return_value = mock_client_instance
        
        # Test exception is raised
        with self.assertRaises(SaasException) as ctx:
            plugin.update_password(Secret("NewPassword123"))
        self.assertIn("Failed to update password", str(ctx.exception))

    @patch('servicenow_users.ServiceNowClient')
    def test_change_password_success(self, mock_servicenow_client):
        """Test successful password change."""
        plugin = self.plugin()
        
        # Mock the client and response
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        mock_session = MagicMock()
        mock_session.patch.return_value = mock_response
        
        mock_client_instance = MagicMock()
        mock_client_instance.session = mock_session
        
        # Mock GlideRecord for user_sys_id
        mock_gr = MagicMock()
        mock_gr.get.return_value = True
        mock_gr.get_value.return_value = "sys_id_12345"
        mock_client_instance.GlideRecord.return_value = mock_gr
        
        mock_servicenow_client.return_value = mock_client_instance
        
        # Test password change
        plugin.change_password()
        
        # Verify the patch call was made
        mock_session.patch.assert_called_once()

    def test_change_password_no_new_password(self):
        """Test change password with no new password set."""
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=None,  # No new password
            prior_password=None
        )
        
        config_record = MagicMock()
        config_record.get_custom_field_value.side_effect = [
            "admin_user", "admin_password", "dev12345"
        ]
        
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as ctx:
            plugin.change_password()
        self.assertIn("New password is not set", str(ctx.exception))

    @patch('servicenow_users.ServiceNowClient')
    def test_rollback_password_success(self, mock_servicenow_client):
        """Test successful password rollback."""
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        
        # Mock the client and response
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        mock_session = MagicMock()
        mock_session.patch.return_value = mock_response
        
        mock_client_instance = MagicMock()
        mock_client_instance.session = mock_session
        
        # Mock GlideRecord for user_sys_id
        mock_gr = MagicMock()
        mock_gr.get.return_value = True
        mock_gr.get_value.return_value = "sys_id_12345"
        mock_client_instance.GlideRecord.return_value = mock_gr
        
        mock_servicenow_client.return_value = mock_client_instance
        
        # Test password rollback
        plugin.rollback_password()
        
        # Verify the patch call was made
        mock_session.patch.assert_called_once()

    def test_rollback_password_no_prior_password(self):
        """Test rollback with no prior password."""
        plugin = self.plugin()  # No prior password
        
        with self.assertRaises(SaasException) as ctx:
            plugin.rollback_password()
        self.assertIn("Cannot rollback password", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
