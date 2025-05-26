import pytest
from unittest.mock import MagicMock, patch
from kdnrm.saas_type import SaasUser, ReturnCustomField, Secret
from kdnrm.exceptions import SaasException
from cisco_apic_password_rotation import SaasPlugin

from kdnrm.log import Log

# Initialize the logger
Log._logger = MagicMock()

@pytest.fixture
def plugin():
    mock_user = MagicMock(spec=SaasUser)
    mock_user.username = Secret("test_user")
    mock_user.new_password = Secret("new_password")
    mock_user.prior_password = Secret("old_password")

    mock_config_record = MagicMock()
    mock_config_record.dict = {
        "fields": [
            {"type": "login", "value": ["admin_user"]},
            {"type": "password", "value": ["admin_pass"]},
            {"type": "url", "value": ["https://apic.example.com"]},
            {"type": "fileRef", "value": ["ssl-certificate.pem"]}
        ]
    }
    mock_config_record.files = [MagicMock(name="ssl-certificate.pem")]
    mock_config_record.files[0].name = "ssl-certificate.pem"
    mock_config_record.download_file_by_title = MagicMock()

    return SaasPlugin(user=mock_user, config_record=mock_config_record)

def test_change_password_success(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        # Mock login and password change responses
        mock_response_login = MagicMock()
        mock_response_login.status_code = 200
        mock_response_login.cookies.get.return_value = "cookie_token"
        mock_response_change = MagicMock()
        mock_response_change.status_code = 200
        mock_post.side_effect = [mock_response_login, mock_response_change]

        plugin.add_return_field = MagicMock()
        plugin.change_password()

        assert plugin._SaasPlugin__cookie_token == "cookie_token"
        plugin.add_return_field.assert_called()

def test_change_password_missing_login(plugin):
    plugin.config_record.dict["fields"] = [
        {"type": "password", "value": ["admin_pass"]},
        {"type": "url", "value": ["https://apic.example.com"]},
        {"type": "fileRef", "value": ["ssl-certificate.pem"]}
    ]
    with pytest.raises(SaasException, match="Missing 'login' field in config record."):
        plugin.change_password()

def test_change_password_missing_file(plugin):
    plugin.config_record.files = []
    with pytest.raises(SaasException, match="Missing 'ssl-certificate.pem' file in config record attachments."):
        plugin.change_password()

def test_fetch_cookie_token_success(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get.return_value = "cookie_token"
        mock_post.return_value = mock_response

        plugin._SaasPlugin__cisco_api_url = "https://apic.example.com"
        plugin.fetch_cookie_token("admin_user", "admin_pass")
        assert plugin._SaasPlugin__cookie_token == "cookie_token"

def test_fetch_cookie_token_fail(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        plugin._SaasPlugin__cisco_api_url = "https://apic.example.com"
        with pytest.raises(SaasException, match="Failed to extract cookie token"):
            plugin.fetch_cookie_token("admin_user", "admin_pass")

def test_change_user_password_success(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        plugin._SaasPlugin__cisco_api_url = "https://apic.example.com"
        plugin._SaasPlugin__cookie_token = "cookie_token"
        plugin.change_user_password("test_user", "new_password")

def test_change_user_password_fail(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        plugin._SaasPlugin__cisco_api_url = "https://apic.example.com"
        plugin._SaasPlugin__cookie_token = "cookie_token"
        with pytest.raises(SaasException, match="Failed to change password."):
            plugin.change_user_password("test_user", "new_password")

def test_rollback_password_success(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        plugin._SaasPlugin__cisco_api_url = "https://apic.example.com"
        plugin._SaasPlugin__cookie_token = "cookie_token"
        plugin.add_return_field = MagicMock()
        plugin.rollback_password()
        plugin.add_return_field.assert_called()

def test_rollback_password_fail(plugin):
    with patch("cisco_apic_password_rotation.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        plugin._SaasPlugin__cisco_api_url = "https://apic.example.com"
        plugin._SaasPlugin__cookie_token = "cookie_token"
        with pytest.raises(SaasException, match="Failed to roll back password."):
            plugin.rollback_password()

def test_add_return_field_valid(plugin):
    field = ReturnCustomField(
        label="apic_url",
        type="url",
        value=Secret("https://apic.example.com")
    )
    plugin.add_return_field(field)
    assert any(f.label == "apic_url" for f in plugin.return_fields)

def test_add_return_field_invalid_type(plugin):
    with pytest.raises(SaasException, match="field must be an instance of ReturnCustomField"):
        plugin.add_return_field("not_a_field")