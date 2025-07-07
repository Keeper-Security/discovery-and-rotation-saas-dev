from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from servicenow_users import SaasPlugin, ServiceNowClient
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from requests import Response
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
                {'type': 'url', 'label': 'ServiceNow Instance URL', 'value': ['https://dev12345.service-now.com']},
            ]
        }
        config_record.title = 'ServiceNow Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # Mock the get_custom_field_value method
        config_record.get_custom_field_value.side_effect = [
            "admin_user",
            "admin_password", 
            "https://dev12345.service-now.com"
        ]

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test that the requirements method returns the correct list of requirements."""
        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("requests", req_list[0])

    def test_change_password_success(self):
        """Test that the change_password method successfully changes the password."""
        plugin = self.plugin()

        with patch.object(ServiceNowClient, "get_sys_id_for_user", return_value="sys_id_12345") as mock_get_sys_id, \
             patch.object(ServiceNowClient, "change_user_password") as mock_change_pw:
            
            plugin.change_password()
            
            mock_get_sys_id.assert_called_once()
            mock_change_pw.assert_called_once_with("sys_id_12345", "NewPassword123")
            self.assertTrue(plugin.can_rollback)
            self.assertEqual(plugin._user_sys_id, "sys_id_12345")

    def test_missing_custom_field_admin_user(self):
        """Test that an exception is raised if the admin username is missing."""
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [],
            'custom': [
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
                {'type': 'url', 'label': 'ServiceNow Instance URL', 'value': ['https://dev12345.service-now.com']},
            ]
        }
        config_record.title = 'ServiceNow Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # Mock missing admin username
        config_record.get_custom_field_value.side_effect = [
            None,  # Missing admin username
            "admin_password",
            "https://dev12345.service-now.com"
        ]

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field Admin Username" not in str(err):
                self.fail("did not message containing 'Admin Username'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_missing_custom_field_admin_password(self):
        """Test that an exception is raised if the admin password is missing."""
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [],
            'custom': [
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin_user']},
                {'type': 'url', 'label': 'ServiceNow Instance URL', 'value': ['https://dev12345.service-now.com']},
            ]
        }
        config_record.title = 'ServiceNow Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # Mock missing admin password
        config_record.get_custom_field_value.side_effect = [
            "admin_user",
            None,  # Missing admin password
            "https://dev12345.service-now.com"
        ]

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field Admin Password" not in str(err):
                self.fail("did not message containing 'Admin Password'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_missing_custom_field_instance_url(self):
        """Test that an exception is raised if the ServiceNow instance URL is missing."""
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [],
            'custom': [
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin_user']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
            ]
        }
        config_record.title = 'ServiceNow Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # Mock missing instance URL
        config_record.get_custom_field_value.side_effect = [
            "admin_user",
            "admin_password",
            None  # Missing instance URL
        ]

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field ServiceNow Instance URL" not in str(err):
                self.fail("did not message containing 'ServiceNow Instance URL'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_invalid_url(self):
        """Test that an exception is raised if the URL is not valid."""
        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [],
            'custom': [
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin_user']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['admin_password']},
                {'type': 'url', 'label': 'ServiceNow Instance URL', 'value': ['bad_url']},
            ]
        }
        config_record.title = 'ServiceNow Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # Mock invalid URL
        config_record.get_custom_field_value.side_effect = [
            "admin_user",
            "admin_password",
            "bad_url"  # Invalid URL
        ]

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "does not appears to be a URL" not in str(err):
                self.fail("did not message containing 'does not appears to be a URL'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_change_password_user_not_found(self):
        """Test that an exception is raised if the user is not found in ServiceNow."""
        plugin = self.plugin()

        with patch.object(ServiceNowClient, "get_sys_id_for_user") as mock_get_sys_id:
            mock_get_sys_id.side_effect = SaasException("User 'jdoe' not found in ServiceNow.")
            
            try:
                plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "not found in ServiceNow" not in str(err):
                    self.fail("did not message containing 'not found in ServiceNow'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_change_password_http_error(self):
        """Test that an exception is raised if the password change fails with HTTP error."""
        plugin = self.plugin()

        with patch.object(ServiceNowClient, "get_sys_id_for_user", return_value="sys_id_12345"), \
             patch.object(ServiceNowClient, "change_user_password") as mock_change_pw:
            
            mock_change_pw.side_effect = SaasException("Unauthorized - check admin credentials (Status 401)")
            
            try:
                plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Unauthorized" not in str(err):
                    self.fail("did not message containing 'Unauthorized'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_change_password_no_sys_id(self):
        """Test that an exception is raised if sys_id cannot be determined."""
        plugin = self.plugin()

        with patch.object(ServiceNowClient, "get_sys_id_for_user", return_value=None):
            try:
                plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Could not determine user sys_id" not in str(err):
                    self.fail("did not message containing 'Could not determine user sys_id'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_rollback_password_success(self):
        """Test that the rollback_password method correctly rolls back the password."""
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        
        # Set up plugin state as if change_password was called
        plugin._user_sys_id = "sys_id_12345"
        plugin._client = ServiceNowClient("admin", "password", "https://test.service-now.com", plugin.user)
        
        with patch.object(ServiceNowClient, "change_user_password") as mock_change_pw:
            plugin.rollback_password()
            mock_change_pw.assert_called_once_with("sys_id_12345", "OldPassword456")

    def test_rollback_password_no_prior_password(self):
        """Test that an exception is raised if there's no prior password to roll back to."""
        plugin = self.plugin()
        
        try:
            plugin.rollback_password()
            raise Exception("should have failed")
        except SaasException as err:
            if "no current password" not in str(err):
                self.fail("did not message containing 'no current password'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_rollback_password_no_client(self):
        """Test that an exception is raised if client is not initialized during rollback."""
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        
        try:
            plugin.rollback_password()
            raise Exception("should have failed")
        except SaasException as err:
            if "client is not set" not in str(err):
                self.fail("did not message containing 'client is not set'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_rollback_password_http_error(self):
        """Test that an exception is raised if rollback fails with HTTP error."""
        plugin = self.plugin(prior_password=Secret("OldPassword456"))
        
        # Set up plugin state
        plugin._user_sys_id = "sys_id_12345"
        plugin._client = ServiceNowClient("admin", "password", "https://test.service-now.com", plugin.user)
        
        with patch.object(ServiceNowClient, "change_user_password") as mock_change_pw:
            mock_change_pw.side_effect = SaasException("Failed to change password")
            
            try:
                plugin.rollback_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Password rollback failed" not in str(err):
                    self.fail("did not message containing 'Password rollback failed'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")


class TestServiceNowClient(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")
        
        self.user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )
        self.client = ServiceNowClient(
            admin_user="admin",
            admin_password="password",
            instance_url="https://dev12345.service-now.com",
            user=self.user
        )

    @patch("servicenow_users.requests.request")
    def test_get_sys_id_for_user_success(self, mock_request):
        """Test successful retrieval of sys_id for user."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": [{"sys_id": "sys_id_12345"}]
        }
        mock_request.return_value = mock_response

        sys_id = self.client.get_sys_id_for_user()
        self.assertEqual(sys_id, "sys_id_12345")

    @patch("servicenow_users.requests.request")
    def test_get_sys_id_for_user_not_found(self, mock_request):
        """Test user not found scenario."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": []}
        mock_request.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.get_sys_id_for_user()
        self.assertIn("not found in ServiceNow", str(ctx.exception))

    @patch("servicenow_users.requests.request")
    def test_get_sys_id_for_user_http_error(self, mock_request):
        """Test HTTP error during sys_id retrieval."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {}
        mock_response.text = "Unauthorized"
        mock_request.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.get_sys_id_for_user()
        self.assertIn("Unauthorized", str(ctx.exception))

    @patch("servicenow_users.requests.request")
    def test_change_user_password_success(self, mock_request):
        """Test successful password change."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        # Should not raise an exception
        self.client.change_user_password("sys_id_12345", "NewPassword123")

    @patch("servicenow_users.requests.request")
    def test_change_user_password_http_error(self, mock_request):
        """Test HTTP error during password change."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {}
        mock_response.text = "Forbidden"
        mock_request.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.change_user_password("sys_id_12345", "NewPassword123")
        self.assertIn("Forbidden", str(ctx.exception))

    @patch("servicenow_users.requests.request")
    def test_request_exception(self, mock_request):
        """Test network/request exception handling."""
        import requests
        mock_request.side_effect = requests.RequestException("Network error")

        with self.assertRaises(SaasException) as ctx:
            self.client.get_sys_id_for_user()
        self.assertIn("API request failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
