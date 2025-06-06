import pytest
from unittest.mock import MagicMock, patch
from kdnrm.saas_type import SaasUser, ReturnCustomField, Secret
from kdnrm.exceptions import SaasException
from okta_user_password_rotation import SaasPlugin, OktaClient
from kdnrm.log import Log

Log._logger = MagicMock()

@pytest.fixture
def plugin():
    mock_user = MagicMock(spec=SaasUser)
    mock_user.username = Secret("test_user")
    mock_user.new_password = Secret("new_password")
    mock_user.prior_password = Secret("old_password")

    mock_config_record = MagicMock()
    def get_config(key, single=True):
        mapping = {
            "subdomain": "example.okta.com",
            "api_token": "fake_token"
        }
        return mapping.get(key)
    mock_config_record.get_custom_field_value.side_effect = get_config
    plugin = SaasPlugin(user=mock_user, config_record=mock_config_record)
    plugin.get_config = MagicMock(side_effect=get_config)
    return plugin

def test_change_password_success(plugin):
    with patch("okta_user_password_rotation.OktaClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client.change_okta_user_password = MagicMock()
        mock_client_class.return_value = mock_client

        plugin.change_password()

        mock_client.change_okta_user_password.assert_called_once()
        assert any(f.label == "subdomain" for f in plugin.return_fields)

def test_change_password_missing_fields(plugin):
    plugin.get_config = MagicMock(return_value=None)
    with patch("okta_user.okta_user_password_rotation.OktaClient"):
        with pytest.raises(SaasException, match="Password change failed: Missing fields 'subdomain' or 'api_token'"):
            plugin.change_password()

def test_add_return_field_valid(plugin):
    field = ReturnCustomField(
        label="subdomain",
        type="text",
        value=Secret("example.okta.com")
    )
    plugin.return_fields = []
    # Patch to append to return_fields
    def add_field(field):
        plugin.return_fields.append(field)
    plugin.add_return_field = add_field
    plugin.add_return_field(field)
    assert any(f.label == "subdomain" for f in plugin.return_fields)

def test_add_return_field_invalid_type(plugin):
    with pytest.raises(SaasException, match="Error adding return field:"):
        plugin.add_return_field("not_a_field")

def test_rollback_password_success(plugin):
    with patch("okta_user.okta_user_password_rotation.OktaClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client.change_okta_user_password = MagicMock()
        plugin._client = mock_client

        plugin.user.prior_password = Secret("old_password")
        plugin.rollback_password()

        mock_client.change_okta_user_password.assert_called_once()
        # You can add more assertions as needed

def test_rollback_password_no_prior(plugin):
    plugin.user.prior_password = None
    with pytest.raises(Exception):
        plugin.rollback_password()