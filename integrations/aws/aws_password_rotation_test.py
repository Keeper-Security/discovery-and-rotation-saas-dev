import pytest
from unittest.mock import MagicMock, patch
from kdnrm.saas_type import SaasUser, ReturnCustomField, Secret
from kdnrm.exceptions import SaasException
from aws_password_rotation import SaasPlugin

from kdnrm.log import Log

# Initialize the logger
Log._logger = MagicMock()

@pytest.fixture
def plugin():
    mock_user = MagicMock(spec=SaasUser)
    mock_user.username = Secret("aws_user")
    mock_user.new_password = Secret("new_pass")
    mock_user.prior_password = Secret("old_pass")
    mock_config_record = MagicMock()
    # get_config will be called on the plugin, so we can patch it directly
    plugin = SaasPlugin(user=mock_user, config_record=mock_config_record)
    plugin.get_config = MagicMock(side_effect=lambda key: {
        "aws_access_key_id": "access",
        "aws_secret_access_key": "secret",
        "cloud_region": "us-west-2"
    }.get(key))
    return plugin

def test_change_password_success(plugin):
    with patch("aws_password_rotation.boto3.client") as mock_client:
        mock_iam = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_client.side_effect = [mock_iam, mock_sts]

        plugin.change_password()

        mock_client.assert_any_call(
            'iam',
            aws_access_key_id="access",
            aws_secret_access_key="secret",
            region_name="us-west-2"
        )
        mock_client.assert_any_call('sts')
        mock_iam.update_login_profile.assert_called_once_with(
            UserName="aws_user",
            Password="new_pass",
            PasswordResetRequired=False
        )
        assert any(f.label == "account_id_or_alias" for f in plugin.return_fields)

def test_change_password_missing_config(plugin):
    plugin.get_config = MagicMock(return_value=None)
    with patch("aws_password_rotation.boto3.client"):
        with pytest.raises(SaasException, match="Missing required configuration values."):
            plugin.change_password()

def test_change_password_update_login_profile_error(plugin):
    with patch("aws_password_rotation.boto3.client") as mock_client:
        mock_iam = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_iam.update_login_profile.side_effect = Exception("update error")
        mock_client.side_effect = [mock_iam, mock_sts]
        with pytest.raises(SaasException, match="Password change failed: update error"):
            plugin.change_password()

def test_add_return_field_valid(plugin):
    field = ReturnCustomField(
        label="account_id_or_alias",
        type="secret",
        value=Secret("123456789012")
    )
    plugin.add_return_field(field)
    assert any(f.label == "account_id_or_alias" for f in plugin.return_fields)

def test_add_return_field_invalid_type(plugin):
    with pytest.raises(SaasException, match="field must be an instance of ReturnCustomField"):
        plugin.add_return_field("not_a_field")

def test_rollback_password_success(plugin):
    plugin.user.prior_password = Secret(("first_pass", "old_pass"))
    plugin.user.new_password = Secret("new_pass")
    plugin._client = MagicMock()
    plugin._client.update_login_profile = MagicMock()
    plugin._SaasPlugin__aws_user_login = "aws_user"
    plugin._SaasPlugin__account_id = "123456789012"
    plugin.add_return_field = MagicMock(return_value=None)
    plugin.rollback_password()

    assert plugin.user.new_password.value == "old_pass"

def test_rollback_password_add_return_field_error(plugin):
    plugin.user.prior_password = Secret(("prev1", "old_pass"))
    plugin.user.new_password = Secret("new_pass")
    plugin._client = MagicMock()
    plugin._SaasPlugin__aws_user_login = "aws_user"
    plugin._SaasPlugin__account_id = "123456789012"
    plugin.add_return_field = MagicMock(side_effect=Exception("fail"))

    with pytest.raises(SaasException, match="Error saving add_return_field for rollback: fail"):
        plugin.rollback_password()

    assert plugin.user.new_password.value == "old_pass"

def test_rollback_password_no_prior(plugin):
    plugin.user.prior_password = None
    plugin._client = MagicMock()
    plugin.add_return_field = MagicMock()
    with pytest.raises(SaasException, match="Password Change while rollback failed:"):
        plugin.rollback_password()