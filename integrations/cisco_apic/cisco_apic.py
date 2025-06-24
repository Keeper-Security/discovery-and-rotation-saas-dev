from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
from tempfile import TemporaryDirectory
import requests
import os

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):

    name = "Cisco APIC"
    summary = "Change a user password in Cisco APIC."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self.cookie_token = None
        self.cisco_api_url = None

        self.temp_dir = TemporaryDirectory()
        self.temp_file = os.path.join(self.temp_dir.name, "certificate.pem")
    
    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="apic_admin",
                label="Admin Name",
                desc="A user with administrative ",
                required=True
            ),
            SaasConfigItem(
                id="apic_password",
                label="Admin Password",
                desc="Password for the APIC Admin.",
                is_secret=True,
                required=True
            ),
            SaasConfigItem(
                id="apic_private_key",
                label="Certificate",
                desc="The certificate from the Admin -> Authentication -> SAML Management.",
                type="multiline",
                is_secret=True,
                required=True
            ),
            SaasConfigItem(
                id="apic_url",
                label="URL",
                desc="URL",
                type="url",
                required=True
            )
        ]
    
    @property
    def can_rollback(self) -> bool:
        return True

    def change_password(self):
        """
        Change the password for the Cisco APIC Plugin user.
        This method connects to the Cisco APIC Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Cisco APIC Plugin user")

        private_key = self.get_config("apic_private_key")
        print(">>>>>", private_key)
        if "BEGIN CERTIFICATE" not in private_key:
            raise Exception("The certificate is missing BEING CERTIFICATE. "
                            "Does the Certificate field contain a certificate?")

        with open(self.temp_file, "w") as fh:
            fh.write(private_key)
            fh.close()

        self.cisco_api_url = self.get_config("apic_url")
        self.fetch_cookie_token(
            login=self.get_config("apic_admin"),
            password=self.get_config("apic_password"),
        )
        username = self.user.username.value
        new_password = self.user.new_password.value
        self.change_user_password(username, new_password)

        Log.debug(f"Password changed successfully for user {username}")

        self.add_return_field(
            ReturnCustomField(
                label="apic_url",
                type="url",
                value=Secret(self.cisco_api_url)
            )
        )

    def fetch_cookie_token(self, login: str, password: str):
        """
        Extract the cookie token for the Cisco APIC Plugin user.
        """
        Log.info("Extracting cookie token for Cisco APIC Plugin user")

        login_url = f"{self.cisco_api_url}/api/aaaLogin.json"
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": login,
                    "pwd": password
                }
            }
        }
        response = requests.post(login_url, json=payload, verify=self.temp_file)
        if response.status_code == 200:
            cookie = response.cookies.get('APIC-cookie')
            if not cookie:
                Log.error("Failed to extract cookie token from response.")
                raise SaasException("Failed to extract cookie token")
            self.cookie_token = cookie
        else:
            Log.error(f"Failed to extract cookie token: StatusCode {response.status_code} - "
                      f"Message: {response.text}")
            raise SaasException("Failed to extract cookie token")
    
    def change_user_password(self, username: str, new_password: str):
        """
        Change the password for the specified user.
        """
        Log.info(f"Changing password for user {username}")

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
        response = requests.post(change_password_url, json=payload, headers=headers, verify=self.temp_file)
        if response.status_code == 200:
            Log.info("Password changed successfully.")
        else:
            Log.error(f"Failed to change password with status code: {response.status_code} - {response.text}")
            raise SaasException("Failed to change password.")

    def rollback_password(self):

        if self.user.prior_password is None:
            raise SaasException(f"There is no current password. Cannot rotate back to prior password.")

        Log.debug("Rolling back password for Cisco APIC Plugin  user")
        change_password_url = f"{self.cisco_api_url}/api/node/mo/uni/userext/user-{self.user}.json"
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": self.user.username.value,
                    "pwd": self.user.prior_password.value
                }
            }
        }
        headers = {
            'Cookie': f'APIC-Cookie={self.cookie_token}'
        }
        response = requests.post(change_password_url, json=payload, headers=headers, verify=self.temp_file)
        if response.status_code == 200:
            Log.info("Password rolled back successfully.")
        else:
            Log.error(f"Failed to roll back password: {response.text}")
            raise SaasException("Failed to roll back password.")

        Log.debug(f"Adding return field")
        self.add_return_field(
            ReturnCustomField(
                label="APIC Website",
                type="url",
                value=Secret(self.cisco_api_url)
            )
        )
