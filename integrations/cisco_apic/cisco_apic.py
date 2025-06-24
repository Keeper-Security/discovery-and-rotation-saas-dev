from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem, SaasConfigEnum
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
from tempfile import TemporaryDirectory
import requests
import json
import os

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

import urllib3
urllib3.disable_warnings()


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
                desc="A user with an administrative role.",
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
                id="apic_url",
                label="URL",
                desc="The URL to the APIC server.",
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="verify_ssl",
                label="Verify SSL",
                desc="Verify that the SSL certificate is valid: "
                     "'True' will validate certificates, "
                     "'False' will allow self-signed certificates.",
                type="enum",
                required=False,
                default_value="False",
                enum_values=[
                    SaasConfigEnum(
                        value="False",
                        desc="Do not validate the SSL certificate. This will allow self-signed certificates."
                    ),
                    SaasConfigEnum(
                        value="True",
                        desc="Validate the SSL certificate. Self-signed certificates are not allowed."
                    ),
                ]
            )
        ]

    @staticmethod
    def _raise_cisco_exception(error_data: bytes):
        error_data = json.loads(error_data)
        Log.error(error_data)

        if "imdata" in error_data:
            errors = []
            for item in error_data.get("imdata", []):
                error = item.get("error")
                if error is not None:
                    attributes = error.get("attributes")
                    if attributes is not None:
                        text = attributes.get("text")
                        if text is not None:
                            errors.append(text)
            if len(errors) > 0:
                raise SaasException(". ".join(errors) + ".")

    @property
    def can_rollback(self) -> bool:
        change_password_url = f"{self.get_config('apic_url')}/api/mo/uni/userext/pwdprofile.json"
        headers = {
            'Cookie': f'APIC-Cookie={self.cookie_token}'
        }
        response = requests.get(change_password_url, headers=headers, verify=self.verify_ssl)
        if response.status_code == 200:
            password_policy = json.loads(response.content)
            for item in password_policy.get("imdata", []):
                profile = item.get("aaaPwdProfile")
                if profile is not None:
                    attributes = profile.get("attributes")
                    if attributes is not None:
                        history_count = attributes.get("historyCount")
                        Log.debug(f"history count is {history_count}")
                        try:
                            history_count = int(history_count)
                            if history_count == 0:
                                Log.debug("able to rollback since history count is 0")
                                return True
                        except (Exception,):
                            pass
        try:
            self._raise_cisco_exception(response.content)
        except Exception as err:
            Log.error(f"Failed to get password policy: {err}")
            return False

        Log.error(f"Failed to get password policy: {response.status_code} - {response.text}")
        return False

    @property
    def verify_ssl(self):
        if self.get_config("verify_ssl") == "True":
            return True
        return False

    def fetch_cookie_token(self):

        if self.cookie_token is None:
            login_url = f"{self.get_config('apic_url')}/api/aaaLogin.json"
            payload = {
                "aaaUser": {
                    "attributes": {
                        "name": self.get_config("apic_admin"),
                        "pwd": self.get_config("apic_password")
                    }
                }
            }

            response = requests.post(login_url, json=payload, verify=self.verify_ssl)
            if response.status_code == 200:
                cookie = response.cookies.get('APIC-cookie')
                if not cookie:
                    Log.error("Failed to extract cookie token from response.")
                    raise SaasException("Failed to extract cookie token")
                Log.debug("able to log into Cisco APIC and get a cookie")
                self.cookie_token = cookie
            else:
                self._raise_cisco_exception(response.content)

                Log.error(f"Failed to extract cookie token: StatusCode {response.status_code} - "
                          f"Message: {response.text}")
                raise SaasException("Failed to extract cookie token")

    def change_user_password(self, new_password: Secret):
        """
        Change the password for the specified user.
        """

        username_plaintext = self.user.username.value

        Log.info(f"Changing password for user {username_plaintext}")

        change_password_url = f"{self.get_config('apic_url')}/api/node/mo/uni/userext/user-{username_plaintext}.json"
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": username_plaintext,
                    "pwd": new_password.value
                }
            }
        }
        headers = {
            'Cookie': f'APIC-Cookie={self.cookie_token}'
        }
        response = requests.post(change_password_url, json=payload, headers=headers, verify=self.verify_ssl)
        if response.status_code == 200:
            Log.info("Password changed successfully.")
        else:
            error_data = json.loads(response.content)
            if "imdata" in error_data:
                errors = []
                for item in error_data.get("imdata", []):
                    error = item.get("error")
                    if error is not None:
                        attributes = error.get("attributes")
                        if attributes is not None:
                            text = attributes.get("text")
                            if text is not None:
                                errors.append(text)
                if len(errors) > 0:
                    raise SaasException(". ".join(errors) + ".")

            Log.error(f"Failed to change password with status code: {response.status_code} - {response.text}")
            raise SaasException("Failed to change password.")

    def change_password(self):
        """
        Change the password for the Cisco APIC Plugin user.
        This method connects to the Cisco APIC Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Cisco APIC Plugin user")

        self.fetch_cookie_token()
        self.change_user_password(self.user.new_password)

        Log.debug(f"Password changed successfully for user {self.user.username.value}")

    def rollback_password(self):

        if self.user.prior_password is None:
            raise SaasException(f"There is no current password. Cannot rotate back to prior password.")

        Log.debug("Rolling back password for Cisco APIC Plugin  user")
        self.change_user_password(self.user.prior_password)
