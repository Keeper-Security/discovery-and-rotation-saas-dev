import pytest
from unittest.mock import MagicMock, patch
from kdnrm.saas_type import SaasUser, ReturnCustomField, Secret
from kdnrm.exceptions import SaasException
from snowflake_password_rotation import SaasPlugin

from kdnrm.log import Log

# Initialize the logger
Log._logger = MagicMock()

@pytest.fixture
def plugin():
    mock_user = MagicMock(spec=SaasUser)
    mock_user.username = MagicMock()
    mock_user.username = Secret("test_user")
    mock_user.new_password = MagicMock()
    mock_user.new_password = Secret("new_password")
    mock_user.prior_password = MagicMock()
    mock_user.prior_password = Secret("old_password")

    mock_config_record = MagicMock()
    mock_config_record.dict = {
        "fields": [
            {"type": "login", "value": ["admin_user"]},
            {"type": "password", "value": ["admin_pass"]}
        ],
        "custom": [
            {"label": "snowflake_account_name", "value": ["test_account"]}
        ]
    }

    return SaasPlugin(user=mock_user, config_record=mock_config_record)

def test_change_password_success(plugin):
    with patch("snowflake.connector.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        plugin.change_password()

        mock_connect.assert_called_once_with(
            user="admin_user",
            password="admin_pass",
            account="test_account"
        )
        mock_cursor.execute.assert_called_once_with(
            'ALTER USER "test_user" SET PASSWORD = %s', ("new_password",)
        )
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()

def test_change_password_missing_fields(plugin):
    plugin.config_record.dict = {
        "fields": [
            {"type": "password", "value": ["admin_pass"]}
        ],
        "custom": [
            {"label": "snowflake_account_name", "value": ["test_account"]}
        ]
    }

    with pytest.raises(SaasException, match="Missing 'login' field in config record."):
        plugin.change_password()

def test_rollback_password_success(plugin):
    plugin.user.new_password = Secret("new_password")
    plugin.user.prior_password = Secret("old_password")

    plugin.rollback_password()

    assert plugin.user.new_password.value == "old_password"

def test_rollback_password_no_prior_password(plugin):
    plugin.user.new_password = Secret("new_password")
    plugin.user.prior_password = None
    
    with pytest.raises(SaasException, match="No prior password to roll back to."):
        plugin.rollback_password()

def test_add_return_field_valid(plugin):
    field = ReturnCustomField(
        label="snowflake_account_name",
        type="secret",
        value=Secret("my_account")
    )
    plugin.add_return_field(field)
    assert len(plugin.return_fields) == 1
    assert plugin.return_fields[0].label == "snowflake_account_name"


def test_add_return_field_invalid_type(plugin):
    with pytest.raises(SaasException, match="field must be an instance of ReturnCustomField"):
        plugin.add_return_field("not_a_field")