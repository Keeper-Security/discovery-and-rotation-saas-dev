import unittest
from unittest.mock import MagicMock, patch
from kdnrm.secret import Secret
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from okta_user import SaasPlugin, OktaClient
from kdnrm.log import Log
from requests.models import Response


class OktaPluginTest(unittest.TestCase):

    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(field_values=None) -> SaasPlugin:
        if field_values is None:
            field_values = ["okta-subdomain.okta.com", "FAKE_API_TOKEN"]

        user = SaasUser(
            username=Secret("jdoe@company.com"),
            new_password=Secret("NewPassword123"),
            prior_password=Secret(("SomeOtherPassword", "OldPassword123"))  
        )

        config_record = MagicMock()
        config_record.dict = {
            'fields': [],
            'custom': [
                {'type': 'text', 'label': 'Subdomain', 'value': [field_values[0]]},
                {'type': 'secret', 'label': 'API Token', 'value': [field_values[1]]}
            ]
        }
        config_record.get_custom_field_value.side_effect = field_values
        config_record.title = 'Okta Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        reqs = SaasPlugin.requirements()
        self.assertIn("requests", reqs)

    @patch("okta_user.OktaClient.change_okta_user_password")
    @patch("okta_user.OktaClient._get_user_id", return_value="fake-id")
    def test_change_password_success(self, mock_get_user_id, mock_change_pw):
        plugin = self.plugin(
            field_values=["okta-subdomain.okta.com", "FAKE_API_TOKEN"]
        )
        plugin.user = SaasUser(
            username=Secret("jdoe@company.com"),
            new_password=Secret("NewPassword123"),
            prior_password=Secret(("SomeOther", "OldPassword123"))
        )
        plugin.change_password()

        mock_change_pw.assert_called_once_with(
            username="jdoe@company.com",
            old_password="OldPassword123",
            new_password="NewPassword123"
        )

    @patch("okta_user.requests.get")
    def test_get_user_id_success(self, mock_get):
        okta_client = OktaClient(subdomain="test.okta.com", api_token="api_token")

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "abc123"}
        mock_get.return_value = mock_response

        user_id = okta_client._get_user_id("jdoe@company.com")
        self.assertEqual(user_id, "abc123")

    @patch("okta_user.requests.get")
    def test_get_user_id_not_found(self, mock_get):
        okta_client = OktaClient(subdomain="test.okta.com", api_token="api_token")

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 404
        mock_response.text = "User not found"
        mock_get.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            okta_client._get_user_id("jdoe@company.com")

        self.assertIn("user not found", str(ctx.exception))

    @patch("okta_user.requests.post")
    @patch("okta_user.OktaClient._get_user_id", return_value="fake-id")
    def test_change_password_http_error(self, mock_user_id, mock_post):
        okta_client = OktaClient(subdomain="test.okta.com", api_token="api_token")

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 403
        mock_response.text = "Failure while changing password of user with status code 403"
        mock_post.return_value = mock_response

        with self.assertRaises(SaasException) as ctx:
            okta_client.change_okta_user_password(
                username="jdoe@company.com",
                old_password="OldPassword123",
                new_password="NewPassword123"
            )
        self.assertIn("Failure while changing password of user with status code 403", str(ctx.exception))

    @patch("okta_user.requests.post")
    @patch("okta_user.OktaClient._get_user_id", return_value="fake-id")
    def test_change_password_success_response(self, mock_get_user_id, mock_post):
        okta_client = OktaClient(subdomain="test.okta.com", api_token="api_token")

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        try:
            okta_client.change_okta_user_password(
                username="jdoe@company.com",
                old_password="OldPassword123",
                new_password="NewPassword123"
            )
        except SaasException:
            self.fail("Should not have raised SaasException on success")
    
    def test_plugin_init_missing_required_config(self):
        with self.assertRaises(SaasException) as ctx:
            self.plugin(field_values=[None, None])
        self.assertIn("Subdomain is required", str(ctx.exception))
