import pytest
from unittest.mock import MagicMock, patch
from kdnrm.saas_type import SaasUser, ReturnCustomField, Secret
from kdnrm.exceptions import SaasException
from cognito_password_rotation import SaasPlugin
from kdnrm.log import Log

# Mock logger to avoid actual logging during tests
Log._logger = MagicMock()

@pytest.fixture
def plugin():
    mock_user = MagicMock(spec=SaasUser)
    mock_user.username = Secret("test_user")
    mock_user.new_password = Secret("new_password")
    mock_user.prior_password = Secret("old_password")

    mock_config_record = MagicMock()
    # Simulate get_custom_field_value for config lookups
    def get_custom_field_value(key, single=True):
        mapping = {
            "AWS Access Key ID": "access",
            "aws_access_key_id": "access",
            "AWS Secret Access Key": "secret",
            "aws_secret_access_key": "secret",
            "User Pool ID": "test_pool",
            "user_pool_id": "test_pool",
            "Cloud Region": "us-west-2",
            "cloud_region": "us-west-2",
        }
        return mapping.get(key)
    mock_config_record.get_custom_field_value.side_effect = get_custom_field_value

    return SaasPlugin(user=mock_user, config_record=mock_config_record)

def test_change_password_success(plugin):
    with patch("cognito_password_rotation.boto3.client") as mock_client:
        mock_boto_client = MagicMock()
        mock_client.return_value = mock_boto_client

        plugin.change_password()

        mock_client.assert_called_once_with(
            "cognito-idp",
            aws_access_key_id="access",
            aws_secret_access_key="secret",
            region_name="us-west-2"
        )
        mock_boto_client.admin_set_user_password.assert_called_once_with(
            UserPoolId="test_pool",
            Username="test_user",
            Password="new_password",
            Permanent=True
        )
        assert any(f.label == "cloud_region" for f in plugin.return_fields)

def test_change_password_missing_fields(plugin):
    plugin.get_config = MagicMock(return_value=None)
    with patch("cognito_password_rotation.boto3.client"):
        with pytest.raises(SaasException, match="Missing required fields in config record."):
            plugin.change_password()

def test_add_return_field_valid(plugin):
    field = ReturnCustomField(
        label="cloud_region",
        type="text",
        value="us-west-2"
    )
    plugin.add_return_field(field)
    assert any(f.label == "cloud_region" for f in plugin.return_fields)

def test_add_return_field_invalid_type(plugin):
    with pytest.raises(SaasException, match="field must be an instance of ReturnCustomField"):
        plugin.add_return_field("not_a_field")

def test_rollback_password_success(plugin):
    plugin.user.username = Secret("test_user")
    plugin.user.prior_password = Secret(("ignored", "old_password"))
    plugin.user.new_password = Secret("new_password")
    plugin._client = MagicMock()
    plugin._client.admin_set_user_password = MagicMock()
    plugin._SaasPlugin__user_pool_id = "test_pool"
    plugin._SaasPlugin__cloud_region = Secret("us-west-2")
    plugin.add_return_field = MagicMock()
    plugin.rollback_password()
    plugin._client.admin_set_user_password.assert_called_once_with(
        UserPoolId="test_pool",
        Username="test_user",
        Password="old_password",
        Permanent=True
    )
    assert plugin.user.new_password.value == "old_password"
    plugin.add_return_field.assert_called_once()
    called_field = plugin.add_return_field.call_args[0][0]
    assert isinstance(called_field, ReturnCustomField)
    assert called_field.label == "cloud_region"
    assert called_field.value.value == "us-west-2"
    assert called_field.type == "text"


def test_rollback_password_no_prior_password(plugin):
    plugin.user.prior_password = None
    with pytest.raises(Exception):
        plugin.rollback_password()