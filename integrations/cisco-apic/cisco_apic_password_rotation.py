from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser, SaasConfigEnum
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
try:
    import requests
except ImportError:
    raise SaasException("Missing required module: boto3. Please install it using \"pip install requests\"")
if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
class SaasPlugin(SaasPluginBase):
    name = "Cisco APIC Post Rotation Plugin"
    cookie_token = "<cookie_token>"
    cisco_api_url = "<cisco_api_url>"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
    
    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]
    
    @property
    def can_rollback(self) -> bool:
        return True
    
    def add_return_field(self, field: ReturnCustomField):
        """
        Add a custom field to the return value.
        """
        Log.debug(f"Adding return field")
        try:
            if not isinstance(field, ReturnCustomField):
                raise SaasException("field must be an instance of ReturnCustomField")
            existing_field = next((f for f in self.return_fields if f.label == field.label), None)
            if existing_field:
                existing_field.value = field.value
            else:
                self.return_fields.append(field)
        except Exception as e:
            raise SaasException(f"Error adding return field: {e}")
        Log.debug(f"Added return field")
        
    def change_password(self):
        """
        Change the password for the Cisco APIC Plugin user.
        This method connects to the Cisco APIC Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Cisco APIC Plugin user")
        try:
            cisco_admin_record = self.config_record.dict.get('fields', [])
            if not isinstance(cisco_admin_record, list):
                raise SaasException("Expected 'fields' to be a list in config_record.")
            
            Log.debug(f"Extracting login from config record")
            cisco_admin_username = next((field['value'][0] for field in cisco_admin_record if field['type'] == 'login'), None)
            if not cisco_admin_username:
                raise SaasException("Missing 'login' field in config record.")

            Log.debug(f"Extracting password from config record")
            cisco_admin_pass = next((field['value'][0] for field in cisco_admin_record if field['type'] == 'password'), None)
            if not cisco_admin_pass:
                raise SaasException("Missing 'password' field in config record.")

            Log.debug(f"Extracting cisco apic url")
            cisco_api_url = next((field['value'][0] for field in cisco_admin_record if field['type'] == 'url'), None)
            if not cisco_api_url:
                raise SaasException("Missing 'cisco api url' field in config record.")

            if not all([cisco_admin_record, cisco_admin_username, cisco_admin_pass, cisco_api_url]):
                raise SaasException("Missing required fields in config record.")

            self.cisco_api_url = cisco_api_url
            self.cookie_token = self.extracting_cookie_token(cisco_admin_username, cisco_admin_pass)
            if not self.cookie_token:
                raise SaasException("Failed to extract cookie token.")
            
            Log.debug(f"Extracting new password from config record")
            username = self.user.username.value
            new_password = self.user.new_password.value
            Log.debug(f"New password: {new_password}")
            self.change_user_password(username, new_password)

            Log.debug(f"Password changed successfully for user {username}")
        except Exception as e:
            raise SaasException(f"Password change failed: {e}")
        try:
            Log.debug(f"Adding return field")
            self.add_return_field(
                ReturnCustomField(
                    label="apic_url",
                    type="url",
                    value=Secret(cisco_api_url)
                )
            )
        except Exception as e:
            Log.error(f"Error saving add_return_field: {e.__str__()}")
            raise SaasException(f"Error saving add_return_field: {e}")

    def extracting_cookie_token(self, login: str, password: str) -> str:
        """
        Extract the cookie token for the Cisco APIC Plugin user.
        """
        Log.info("Extracting cookie token for Cisco APIC Plugin user")
        try:
            login_url = f"{self.cisco_api_url}/api/aaaLogin.json"
            payload = {
                "aaaUser": {
                    "attributes": {
                        "name": login,
                        "pwd": password
                    }
                }
            }
            response = requests.post(login_url, json=payload, verify='ssl-certificate.pem')
            if response.status_code == 200:
                cookie = response.cookies.get('APIC-cookie')
                Log.debug(f"Cookie token extracted: {cookie}")
                return cookie
            else:
                Log.error(f"Failed to extract cookie token: status-code {response.status_code} - {response.text}")
                raise SaasException("Failed to extract cookie token")
        except Exception as e:
            Log.error(f"Error changing password: {e.__str__()}")
            raise SaasException(f"Password change failed: {e}")
    
    def change_user_password(self, username: str, new_password: str):
        """
        Change the password for the specified user.
        """
        Log.info(f"Changing password for user {username}")
        try:
            change_password_url = f"{self.cisco_api_url}/api/node/mo/uni/userext/user-{username}.json"
            payload = {
                "aaaUser": {
                    "attributes": {
                        "name": username,
                        "pwd": new_password
                    }
                }
            }
            headers = {
                'Cookie': f'APIC-Cookie={self.cookie_token}'
            }
            response = requests.post(change_password_url, json=payload, headers=headers, verify='ssl-certificate.pem')
            if response.status_code == 200:
                Log.info("Password changed successfully.")
            else:
                Log.error(f"Failed to change password with status code: {response.status_code} - {response.text}")
                raise SaasException("Failed to change password.")
        except Exception as e:
            Log.error(f"Error changing password: {e.__str__()}")
            raise SaasException(f"Password change failed: {e}")
        

    def rollback_password(self):
        try:
            Log.debug("Rolling back password for Cisco APIC Plugin  user")
            change_password_url = f"{self.cisco_api_url}/api/node/mo/uni/userext/user-{self.user}.json"
            payload = {
                "aaaUser": {
                    "attributes": {
                        "name": self.user.username.value,
                        "pwd": self.user.prior_password.value[-1]
                    }
                }
            }
            headers = {
                'Cookie': f'APIC-Cookie={self.cookie_token}'
            }
            response = requests.post(change_password_url, json=payload, headers=headers, verify='ssl-certificate.pem')
            if response.status_code == 200:
                Log.info("Password rolled back successfully.")
            else:
                Log.error(f"Failed to roll back password: {response.text}")
                raise SaasException("Failed to roll back password.")
            try:
                Log.debug(f"Adding return field")
                self.add_return_field(
                    ReturnCustomField(
                        label="apic_url",
                        type="url",
                        value=Secret(cisco_api_url)
                    )
                )
            except Exception as e:
                Log.error(f"Error saving add_return_field: {e.__str__()}")
                raise SaasException(f"Error saving add_return_field: {e}")

        except Exception as e:
            Log.error(f"Error rolling back password: {e.__str__()}")
            raise SaasException(f"Rollback failed: {e}")