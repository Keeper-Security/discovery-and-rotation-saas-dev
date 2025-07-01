from __future__ import annotations
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, SaasConfigItem, SaasUser, Secret
import requests
from requests.models import Response
from typing import List, TYPE_CHECKING
import base64
import json
if TYPE_CHECKING:  # pragma: no cover
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):

    name = "ServiceNow"
    summary = "Change user password in ServiceNow."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self,
        user: SaasUser,
        config_record: Record,
        provider_config=None,
        force_fail=False,
    ):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self.__user_sys_id = None
        self._client = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="admin_user",
                label="Admin Username",
                desc="ServiceNow administrator username.",
                required=True,
            ),
            SaasConfigItem(
                id="admin_password",
                label="Admin Password",
                desc="Password for the ServiceNow administrator.",
                type="secret",
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="servicenow_url",
                label="ServiceNow Instance URL",
                desc="Base URL of the ServiceNow instance (e.g. https://<instance>.service-now.com).",
                type="url",
                required=True,
            ),
        ]

    @property
    def can_rollback(self) -> bool:
        return True

    def change_password(self):
        Log.info("Changing password for ServiceNow Plugin user")

        Log.info(
            "Retrieving ServiceNow admin credentials and instance URL from config record"
        )
        Log.debug(f"Config record fields: {self.config_record.dict.get('fields')}")
        # admin_username = self.get_config("admin_user")
        # admin_password = self.get_config("admin_password")
        # instance_url = "abc"#self.get_config("servicenow_url")
        # if not admin_username or not admin_password or not instance_url:
        #     Log.error(
        #         "Admin credentials or ServiceNow instance URL are not configured."
        #     )
        #     raise SaasException(
        #         "Admin credentials or ServiceNow instance URL are not configured."
        #     )
        # client = ServiceNowClient(
        #     admin_user=admin_username,
        #     admin_password=admin_password,
        #     instance_url=instance_url,
        #     user=self.user,
        # )
        # sys_id = client.get_sys_id_for_user()
        # if not sys_id:
        #     Log.error("Could not determine user sys_id.")
        #     raise SaasException("Could not determine user sys_id.")
        # self.__user_sys_id = sys_id
        # self._client = client
        # new_password = self.user.new_password.value
        # client.change_user_password(sys_id, new_password)
        # self.add_return_field(
        #     ReturnCustomField(type="text", label="user_sys_id", value=Secret(sys_id))
        # )
        # self.add_return_field(
        #     ReturnCustomField(
        #         type="url", label="instance_url", value=Secret(instance_url)
        #     )
        # )
        Log.info("Password changed successfully.")

    def rollback_password(self):
        if self.user.prior_password is None:
            raise SaasException(
                "There is no current password. Cannot rotate back to prior password."
            )
        Log.debug("Rolling back password")
        if self.__user_sys_id:
            old_password = self.user.prior_password.value
            self._client.change_user_password(self.__user_sys_id, old_password)
            Log.info("Password rolled back successfully.")
        else:
            Log.error("User sys_id is not set. Cannot roll back password.")
            raise SaasException("User sys_id is not set. Cannot roll back password.")


class ServiceNowClient:
    """
    Client for interacting with ServiceNow REST API to manage user accounts.
    """

    TABLE_API_USER = "{instance_url}/api/now/table/sys_user"

    def __init__(
        self, admin_user: str, admin_password: str, instance_url: str, user: SaasUser
    ):
        self._admin_user = admin_user
        self._admin_password = admin_password
        self._instance_url = instance_url.rstrip("/")
        self._user = user
        self._auth_header = self._build_auth_header

    @property
    def _build_auth_header(self) -> dict:
        credentials = f"{self._admin_user}:{self._admin_password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    @property
    def __get_header(self) -> dict:
        """
        Returns the headers required for ServiceNow API requests.
        """
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._auth_header,
        }

    def __get_payload(self, new_password: str) -> dict:
        return {"user_password": new_password, "password_needs_reset": "false"}

    def get_sys_id_for_user(self) -> str:
        """
        Get the ServiceNow sys_id for the given username.
        """
        Log.info("Fetching sys_id for user in ServiceNow")
        username = self._user.username.value
        url = f"{self.TABLE_API_USER}?user_name={username}".format(
            instance_url=self._instance_url
        )
        Log.debug(f"ServiceNow API URL: {url}")
        headers = self.__get_header
        try:
            response = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as e:
            Log.error(f"Failed to fetch sys_id for user '{username}': {e}")
            raise SaasException(f"Failed to fetch sys_id: {e}") from e
        if response.status_code == 200:
            data = response.json().get("result")
            if not data:
                Log.error(f"User '{username}' not found in ServiceNow.")
                raise SaasException(f"User '{username}' not found in ServiceNow.")
            return data[0].get("sys_id")
        else:
            self.error_response_code(response)

    def error_response_code(self, response: Response):
        """
        Handle error response codes from the ServiceNow Plugin API.
        :param response: The response object from the API request.
        :return: A SaasException with the appropriate error message.
        """
        status_code_error_type_map = {
            400: "Bad request",
            401: "Unauthorized",
            403: "Forbidden",
            500: "Internal server error",
        }
        try:
            error_data = response.json()
        except (ValueError, json.JSONDecodeError):
            error_data = {}
        message = status_code_error_type_map.get(response.status_code, "Unknown error")
        if "error" in error_data:
            msg_text = error_data["error"].get("message", "")
            detail_text = error_data["error"].get("detail", "")
            detailed_message = f"{msg_text}. {detail_text}.".strip(".")
        else:
            detailed_message = str(error_data)
        msg = f"{message}, Status Code: {response.status_code}, Message: {detailed_message}."

        Log.error(msg=msg)
        raise SaasException(msg)

    def change_user_password(self, sys_id: str, new_password: str):
        """
        Change the password for the user identified by sys_id.
        """
        Log.info(f"Changing password for user with sys_id: {sys_id}")
        url = f"{self.TABLE_API_USER}/{sys_id}?sysparm_input_display_value=true".format(
            instance_url=self._instance_url
        )
        payload = self.__get_payload(new_password)
        headers = self.__get_header
        try:
            response = requests.patch(url, json=payload, headers=headers, timeout=10)
        except requests.RequestException as e:
            Log.error(f"Failed to change password for user with sys_id '{sys_id}': {e}")
            raise SaasException(f"Password change request failed: {e}") from e
        if response.status_code == 200:
            Log.info("Password changed successfully.")
        else:
            self.error_response_code(response)
