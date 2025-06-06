from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser, SaasConfigItem
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
try:
    import requests
except ImportError:
    raise SaasException("Missing required module: okta. Please install it using 'pip install requests'")
if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

OKTA_USER_CHANGE_API_URL = "https://{subdomain}/api/v1/users/{user_id}/credentials/change_password"

class SaasPlugin(SaasPluginBase):
    name = "Okta User Post Rotation Plugin"
    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
    
    @classmethod
    def requirements(cls) -> List[str]:
        return ["okta","asyncio"]
    
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="subdomain",
                label="Subdomain",
                type="text",
                desc="Subdomain of Okta account ended with '.okta.com'",
                required=True
            ),
            SaasConfigItem(
                id="api_token",
                label="API Token",
                desc="API Token from okta",
                type="secret",
                required=True
            )
        ]

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
            raise SaasException(f"Error adding return field: {e}")
        Log.debug(f"Added return field")
        
    def change_password(self):
        """
        Change the password for the AWS Plugin user.
        This method connects to the AWS Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for AWS Plugin user")
        try:
            Log.debug("Fetching Subdomain from keeper config record")
            subdomain = self.get_config("subdomain")
            Log.debug("Fetching API Token from keeper config record")
            api_token = self.get_config("api_token")

            if not subdomain and api_token:
                Log.error("Missing any one of the fields 'subdomain' or 'api_token'")
                raise Exception("Missing fields 'subdomain' or 'api_token'")
            
            self._client = OktaClient(subdomain=subdomain, api_token=api_token)
            username = self.user.username.value
            if not username:
                Log.error("Missing field username from user record")
                raise Exception("Missing fields username")
            
            
            new_password = self.user.new_password.value
            Log.debug(f"New Password {new_password}")
            old_password = self.user.prior_password.value[-1]
            self._client.change_okta_user_password(username=username, old_password=old_password, new_password=new_password)
           
            Log.debug(f"Adding return field")
            self.add_return_field(field=ReturnCustomField(
                label="subdomain",
                type="text",
                value=Secret(subdomain)
            ))
            Log.info("Password changed successfully.")
            raise Exception("Test Error")
        except Exception as e:
            raise SaasException(f"Password change failed: {e}")
        
    def rollback_password(self):
        try:
            Log.debug("Rolling back password for AWS Plugin  user")
            username = self.user.username.value
            new_password = self.user.prior_password.value[-1]
            old_password = self.user.prior_password.value[-1]
            Log.debug(f"New Password: {new_password}, old_password: {old_password}")
            self._client.change_okta_user_password(username=username, old_password=old_password, new_password=new_password)
            Log.info("Password rolled back successfully.")
        except Exception as e:
            raise SaasException(f"Rollback failed: {e}")


class OktaClient:
    def __init__(self, subdomain: str, api_token: str) -> str:
        self.__subdomain = subdomain
        self.__api_token = api_token

    def __get_user_id(self, username):
        """
        Fetch the Okta user ID using the user's login (email).
        
        Args:
            username (str): The user's login/email.
        
        Returns:
            str: The Okta user ID.

        Raises:
            SaasException: If the request fails or the user is not found.
        """
        try:
            url = f"https://{self.__subdomain}/api/v1/users/{username}"
            headers = self.__get_header()

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                return response.json().get("id")
            elif response.status_code == 404:
                Log.error(f"{username} user not found")

            Log.error(
                f"Failed to fetch user ID. "
                f"Status Code: {response.status_code}, Response: {response.text}"
            )
            raise SaasException("Error while fetching user details")

        except Exception as e:
            Log.error(f"Exception while fetching user ID: {e}")
            raise SaasException(f"Error while fetching user details: {e}")
        
    def change_okta_user_password(self, username: str, old_password: str, new_password: str):
        """
        Change the user's password in Okta.
        """
        Log.debug(f"Changing okta user's password")
        try:
            user_id = self.__get_user_id(username=username)
            url = self.__get_url(user_id=user_id)
            payload = self.__get_payload(old_password=old_password, new_password=new_password)
            headers = self.__get_header()

            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                Log.debug(f"Response status code 200")
            else:
                Log.error(f"Error while changing password, Status Code: {response.status_code} \n Message: {response.text} ")
                raise Exception(f"Failure while changing password")
            
        except Exception as e:
            raise SaasException("Failure while changing password with status code {response.status_code}")
        
    def __get_url(self, user_id: str) -> str: 
        return OKTA_USER_CHANGE_API_URL.format(subdomain=self.__subdomain, user_id=user_id)

    def __get_payload(self, old_password: str, new_password: str) -> dict[str, any]:
        return {
        "oldPassword": {
            "value": f"{old_password}"
        },
        "newPassword": {
            "value": f"{new_password}"
        },
        "revokeSessions": True
        }

    def __get_header(self) -> dict[str, str]:
        return {
        "Content-Type": "application/json",
        "Authorization": f"SSWS {self.__api_token}"
        }