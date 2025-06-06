from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser, SaasConfigItem
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
import asyncio


try:
    from azure.identity import ClientSecretCredential
    from msgraph import GraphServiceClient
    from msgraph.generated.models.user import User
    from msgraph.generated.models.password_profile import PasswordProfile
    
except ImportError:
    raise SaasException("Missing required modules, Please install the required modules from requirements.txt using 'pip install -r requirements.txt'")

if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

LOGIN_URL = "https://login.microsoftonline.com/"
SCOPES = ['https://graph.microsoft.com/.default']
class SaasPlugin(SaasPluginBase):

    name = "Azure Post Rotation Plugin"
    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="tenant_id",
                label="Tenant ID",
                desc="Admin Tenant ID",
                required=True,
                type="secret"
            ),
            SaasConfigItem(
                id="client_id",
                label="Client ID",
                desc="Admin Client ID",
                required=True,
                type="secret"
            ),
            SaasConfigItem(
                id="client_secret",
                label="Client Secret",
                desc="Admin Client Secret",
                required=True,
                type="secret"
            ),
        ]

    @classmethod
    def requirements(cls) -> List[str]:
        return ["azure-identity", "msgraph-sdk", "pytest"]
    
    @property
    def can_rollback(self) -> bool:
        return True
    
    def add_return_field(self, field: ReturnCustomField):
        """
        Add a custom field to the return value.
        """
        Log.debug(f"Adding return field")
        try:
            self.return_fields.append(field)
        except Exception as e:
            Log.error(f"Error while append fields {e}")
            raise SaasException(f"Error adding return field: {e}")
        Log.debug(f"Added return field")
        
    def change_password(self):
        """
        Change the password for the Azure Entra ID Plugin user.
        This method connects to the Azure Entra ID Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Azure Entra ID Plugin user")
        try:
            tenant_id = self.get_config("tenant_id")
            client_id = self.get_config("client_id")
            client_secret = self.get_config("client_secret")
            if not (tenant_id and client_id and client_secret):
                Log.error(f"'tenant_id', 'client_id' and 'client_secret' are all required fields. One or few of them are missing")
                raise SaasException("Missing required fields from config_record")
            
            self.__azure_client = AzureClient(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
            new_password = self.user.new_password.value
            username = self.user.username.value
            asyncio.run(self.__azure_client.change_password_by_admin(username=username, new_password=new_password))
            Log.info("Password changed successfully.")
        except Exception as e:
            Log.error(f"Error while changing password by admin {e}")
            raise SaasException(f"Password change failed: {e}")
        try:
            Log.debug(f"Adding return field")
            self.add_return_field(ReturnCustomField(
                label="login_url",
                type="url",
                value=Secret(LOGIN_URL)
            ))
        except Exception as e:
            Log.error(f"Error while add_return_field: {e}")
            raise SaasException(f"Error saving add_return_field: {e}")
    
    def rollback_password(self):
        try:
            Log.debug("Rolling back password for Azure Entra ID Plugin user")
            asyncio.run(self.__azure_client.change_password_by_admin(self.user.username.value, self.user.prior_password.value[-1]))
            Log.info("Password rolled back successfully")
        except Exception as e:
            Log.error(f"Error while updating password in rollback {e}")
            raise SaasException(f"Rollback failed: {e}")
        
   
class AzureClient:
    def __init__(self, tenant_id, client_id, client_secret):
       self.__azure_credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
            )

    async def change_password_by_admin(self, username, new_password):
        Log.info("Rotating user password by admin credentials")
        try:
            client = GraphServiceClient(credentials=self.__azure_credential, scopes=SCOPES)
            request_body = User(
                password_profile = PasswordProfile(
                    force_change_password_next_sign_in = False,
                    password = new_password,
                ),
            )
            result = await client.users.by_user_id(user_id=username).patch(request_body)
            Log.debug(f"Successfully rotated password by admin credentials {result}")
        except Exception as e:
            Log.error(f"Error while rotating password by admin {e}")
            raise SaasException(f"Failed to update password by admin {e}")
        
