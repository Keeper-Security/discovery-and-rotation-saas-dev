from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from kdnrm.secret import Secret
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from dell_idrac import SaasPlugin, DelliDRACClient, ACCOUNT_SERVICE_URL
from requests.exceptions import RequestException
from kdnrm.log import Log


class DellIDRACTest(unittest.TestCase):

    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Secret = None):

        user = SaasUser(
            username=Secret("testuser"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MagicMock()
        config_record.dict = {
            'custom': [
                {'type': 'text', 'label': 'Admin Username', 'value': ['admin']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['adminpass']},
                {'type': 'secret', 'label': 'iDRAC IP', 'value': ['1.2.3.4']},
                {'type': 'url', 'label': 'User ID', 'value': ["42"]},
            ]
        }
        config_record.title = 'Dell iDRAC Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # The param checker does not like MagicMock.
        config_record.get_custom_field_value.side_effect = [
            "admin",
            "adminpass",
            "1.2.3.4",
            "42"
        ]

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        req_list = SaasPlugin.requirements()
        self.assertEqual(req_list, ["requests"])

    def test_change_password_success(self):
        plugin = self.plugin()
        with patch.object(DelliDRACClient, "get_user_id_from_user_fields", return_value="42"), \
             patch.object(DelliDRACClient, "check_username_by_id"), \
             patch.object(DelliDRACClient, "change_dell_idrac_user_password") as mock_change_pw:
            plugin.change_password()
            mock_change_pw.assert_called_once_with("42", "NewPassword123")
            self.assertEqual(plugin._SaasPlugin__user_id, "42")
            self.assertTrue(any(f.label == "user_id" for f in plugin.return_fields))

        self.assertTrue(plugin.can_rollback)

    def test_missing_custom_field_admin_name(self):
        """
        Missing the custom field for the admin
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'custom': [
                {'type': 'secret', 'label': 'Admin Password', 'value': ['adminpass']},
                {'type': 'secret', 'label': 'iDRAC IP', 'value': ['1.2.3.4']},
                {'type': 'url', 'label': 'User ID', 'value': ["42"]},
            ]
        }
        config_record.title = 'APIC Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # The param checker does not like MagicMock.
        config_record.get_custom_field_value.side_effect = [
            None,
            "adminpass",
            "1.2.3.4",
            "42"
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
        """
        Missing the custom field for the admin password
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'custom': [
                {'type': 'secret', 'label': 'Admin Username', 'value': ['admin']},
                {'type': 'secret', 'label': 'iDRAC IP', 'value': ['1.2.3.4']},
                {'type': 'url', 'label': 'User ID', 'value': ["42"]},
            ]
        }
        config_record.title = 'APIC Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # The param checker does not like MagicMock.
        config_record.get_custom_field_value.side_effect = [
            "admin",
            None,
            "1.2.3.4",
            "42"
        ]

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field Admin Password" not in str(err):
                self.fail("did not message containing 'Admin Password'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_missing_custom_field_idrac_ip(self):
        """
        Missing the custom field for the iDRAC IP
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MagicMock()
        config_record.dict = {
            'custom': [
                {'type': 'secret', 'label': 'Admin Username', 'value': ['admin']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['adminpass']},
                {'type': 'url', 'label': 'User ID', 'value': ["42"]},
            ]
        }
        config_record.title = 'APIC Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # The param checker does not like MagicMock.
        config_record.get_custom_field_value.side_effect = [
            "admin",
            "adminpass",
            None,
            "42"
        ]

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field iDRAC IP" not in str(err):
                self.fail("did not message containing 'iDRAC IP'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_change_password_missing_user_id(self):
        plugin = self.plugin()

        plugin.get_config = MagicMock(side_effect=lambda key, single=True: {
            "login": "admin",
            "password": "adminpass",
            "idrac_ip": "1.2.3.4",
            "user_id": None
        }.get(key))

        with patch.object(DelliDRACClient, "get_user_id_from_user_fields", return_value=None):
            with self.assertRaises(SaasException) as ctx:
                plugin.change_password()
            self.assertIn("Cannot determine user_id", str(ctx.exception))

    def test_change_password_username_mismatch(self):
        plugin = self.plugin()
        with patch.object(DelliDRACClient, "get_user_id_from_user_fields", return_value="42"), \
             patch.object(DelliDRACClient, "check_username_by_id",
                          side_effect=SaasException("Username mismatch with user_id")):
            with self.assertRaises(SaasException) as ctx:
                plugin.change_password()
            self.assertIn("Username mismatch with user_id", str(ctx.exception))

    def test_change_password_http_error(self):
        plugin = self.plugin()
        with patch.object(DelliDRACClient, "get_user_id_from_user_fields", return_value="42"), \
             patch.object(DelliDRACClient, "check_username_by_id"), \
             patch.object(DelliDRACClient, "change_dell_idrac_user_password",
                          side_effect=SaasException("Password rotation failed: 500")):
            with self.assertRaises(SaasException) as ctx:
                plugin.change_password()
            self.assertIn("Password rotation failed", str(ctx.exception))

    def test_rollback_password_success(self):
        plugin = self.plugin(prior_password=Secret("OldPassword123"))
        plugin._client = MagicMock()
        plugin._SaasPlugin__user_id = "42"
        plugin.user.prior_password = Secret(("SomeOtherPassword", "OldPassword123"))
        plugin._client.change_dell_idrac_user_password = MagicMock()
        plugin.rollback_password()
        plugin._client.change_dell_idrac_user_password.assert_called_once_with("42", "OldPassword123")

    def test_rollback_password_no_prior(self):
        plugin = self.plugin(prior_password=None)
        plugin._client = MagicMock()
        plugin._SaasPlugin__user_id = "42"
        plugin.user.prior_password = None
        with self.assertRaises(Exception):
            plugin.rollback_password()

    def test_rollback_password_http_error(self):
        plugin = self.plugin(prior_password=Secret("OldPassword123"))
        plugin._client = MagicMock()
        plugin._SaasPlugin__user_id = "42"
        plugin.user.prior_password = Secret(("SomeOtherPassword", "OldPassword123"))
        plugin._client.change_dell_idrac_user_password.side_effect = \
            SaasException("Password change request failed: 500")
        with self.assertRaises(SaasException) as ctx:
            plugin.rollback_password()
        self.assertIn("Rollback failed", str(ctx.exception))


class DelliDRACClientTest(unittest.TestCase):

    def setUp(self):
        user = MagicMock()
        user.username.value = "testuser"
        self.client = DelliDRACClient(
            admin_username="admin",
            admin_password="adminpass",
            idrac_ip="1.2.3.4",
            user=user
        )

    @patch("dell_idrac.requests.get")
    def test_check_username_by_id_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"UserName": "testuser"}
        mock_get.return_value = mock_response
        self.client.check_username_by_id("42")

    @patch("dell_idrac.requests.get")
    def test_check_username_by_id_mismatch(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"UserName": "otheruser"}
        mock_get.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.check_username_by_id("42")
        self.assertIn("Username mismatch with user_id", str(ctx.exception))

    @patch("dell_idrac.requests.get")
    def test_check_username_by_id_not_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.check_username_by_id("42")
        self.assertIn("User not present in Dell iDRAC", str(ctx.exception))

    @patch("dell_idrac.requests.get")
    def test_check_username_by_id_internal_server_error(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.check_username_by_id("42")
        self.assertIn("Internal server error while verifying user ID", str(ctx.exception))

    @patch("dell_idrac.requests.get", side_effect=RequestException("Network error"))
    def test_check_username_by_id_exception(self, mock_get):
        with self.assertRaises(SaasException) as ctx:
            self.client.check_username_by_id("42")
        self.assertIn("Request failed while verifying user ID: Network error", str(ctx.exception))

    @patch("dell_idrac.requests.patch")
    def test_change_dell_idrac_user_password_success(self, mock_patch):
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_patch.return_value = mock_response
        self.client.change_dell_idrac_user_password("42", "newpass")
        expected_url = ACCOUNT_SERVICE_URL.format(idrac_ip=self.client._DelliDRACClient__idrac_ip, user_id="42")
        expected_payload = {"Password": "newpass"}
        expected_auth = (self.client._DelliDRACClient__admin_username, self.client._DelliDRACClient__admin_password)
        mock_patch.assert_called_once_with(
            expected_url,
            json=expected_payload,
            auth=expected_auth,
            timeout=10,
        )

    @patch("dell_idrac.requests.patch")
    def test_change_dell_idrac_user_password_failure(self, mock_patch):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_patch.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            self.client.change_dell_idrac_user_password("42", "newpass")
        self.assertIn("Password rotation failed: 400 - Bad Request", str(ctx.exception))

    @patch("dell_idrac.requests.patch", side_effect=Exception("Network error"))
    def test_change_dell_idrac_user_password_exception(self, mock_patch):
        with self.assertRaises(SaasException) as ctx:
            self.client.change_dell_idrac_user_password("42", "newpass")
        self.assertIn("Password change request failed: Network error", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
