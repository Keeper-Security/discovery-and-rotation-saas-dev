import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from kdnrm.saas_type import SaasUser, ReturnCustomField, Secret
from kdnrm.exceptions import SaasException
from azure_user.azure_user_password_rotation import SaasPlugin, AzureClient, SCOPES, LOGIN_URL
from kdnrm.log import Log

Log._logger = MagicMock()

@pytest.fixture
def plugin():
    mock_user = MagicMock(spec=SaasUser)
    mock_user.username = Secret("test_user")
    mock_user.new_password = Secret("new_password")
    mock_user.prior_password = Secret(("older_password", "old_password"))

    mock_config_record = MagicMock()
    def get_config(key, single=True):
        mapping = {
            "tenant_id": "tenant",
            "client_id": "client",
            "client_secret": "secret"
        }
        return mapping.get(key)
    mock_config_record.get_custom_field_value.side_effect = get_config
    plugin = SaasPlugin(user=mock_user, config_record=mock_config_record)
    plugin.get_config = MagicMock(side_effect=get_config)
    return plugin

def test_change_password_success(plugin):
    with patch("azure_user.azure_user_password_rotation.AzureClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client.change_password_by_admin = AsyncMock()
        mock_client_class.return_value = mock_client

        plugin.change_password()
        mock_client.change_password_by_admin.assert_awaited_once_with(
            username="test_user",
            new_password="new_password"
        )
        assert any(f.label == "login_url" and Secret.get_value(f.value) == LOGIN_URL for f in plugin.return_fields)

def test_change_password_missing_fields(plugin):
    plugin.get_config = MagicMock(return_value=None)
    with patch("azure_user.azure_user_password_rotation.AzureClient"):
        with pytest.raises(SaasException, match="Missing required fields from config_record"):
            plugin.change_password()

def test_add_return_field_valid(plugin):
    field = ReturnCustomField(
        label="login_url",
        type="url",
        value=Secret(LOGIN_URL)
    )
    plugin.add_return_field(field)
    assert any(f.label == "login_url" for f in plugin.return_fields)

def test_rollback_password_success(plugin):
    with patch("azure_user.azure_user_password_rotation.AzureClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client.change_password_by_admin = AsyncMock()
        plugin._SaasPlugin__azure_client = mock_client
        plugin.rollback_password()
        mock_client.change_password_by_admin.assert_awaited_once_with(
            "test_user",
            "old_password"
        )

def test_rollback_password_no_prior(plugin):
    plugin.user.prior_password = None
    with pytest.raises(Exception):
        plugin.rollback_password()


@pytest.mark.asyncio
async def test_change_password_by_admin_success():
    client_secret_credential = MagicMock()
    azure_client = AzureClient(tenant_id="tenant", client_id="client", client_secret="secret")
    azure_client._AzureClient__azure_credential = client_secret_credential  # Patch credential if needed

    with patch("azure_user.azure_user_password_rotation.GraphServiceClient") as mock_graph_client_class:
        mock_graph_client = MagicMock()
        mock_users = MagicMock()
        mock_by_user_id = MagicMock()
        mock_patch = AsyncMock(return_value="success")

        mock_graph_client.users = mock_users
        mock_users.by_user_id.return_value = mock_by_user_id
        mock_by_user_id.patch = mock_patch
        mock_graph_client_class.return_value = mock_graph_client
        result = await azure_client.change_password_by_admin("test_user", "new_password")
        mock_graph_client_class.assert_called_once_with(credentials=client_secret_credential, scopes=SCOPES)
        mock_users.by_user_id.assert_called_once_with(user_id="test_user")
        mock_by_user_id.patch.assert_awaited_once()

@pytest.mark.asyncio
async def test_change_password_by_admin_failure():
    client_secret_credential = MagicMock()
    azure_client = AzureClient(tenant_id="tenant", client_id="client", client_secret="secret")
    azure_client._AzureClient__azure_credential = client_secret_credential

    with patch("azure_user.azure_user_password_rotation.GraphServiceClient") as mock_graph_client_class:
        mock_graph_client = MagicMock()
        mock_users = MagicMock()
        mock_by_user_id = MagicMock()
        mock_patch = AsyncMock(side_effect=Exception("API error"))
        mock_graph_client.users = mock_users
        mock_users.by_user_id.return_value = mock_by_user_id
        mock_by_user_id.patch = mock_patch
        mock_graph_client_class.return_value = mock_graph_client

        with pytest.raises(SaasException, match="Failed to update password by admin"):
            await azure_client.change_password_by_admin("test_user", "new_password")