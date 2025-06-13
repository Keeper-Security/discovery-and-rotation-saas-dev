from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser, SaasConfigItem
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log

try:
    import requests
except ImportError:
    raise SaasException('Missing required module: requests. Please install it using "pip install requests"')

if TYPE_CHECKING:
    from keeper_secrets_manager_core.dto.dtos import Record

ACCOUNT_SERVICE_URL = "https://{idrac_ip}/redfish/v1/AccountService/Accounts/{user_id}"


class SaasPlugin(SaasPluginBase):
    name = "Dell iDRAC Post Rotation Plugin"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self.__user_id = "<User_Id_of_rotated_user>"
        self._client = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(id="login", label="UserName", desc="Admin UserName", required=True),
            SaasConfigItem(id="password", label="Password", desc="Admin Dell iDRAC Password", type="secret", required=True),
            SaasConfigItem(id="idrac_ip", label="iDRAC IP", desc="Admin Dell iDRAC IP", type="secret", required=True),
            SaasConfigItem(id="user_id", label="USER_ID", desc="User ID", type="text", required=False),
        ]

    @property
    def can_rollback(self) -> bool:
        return True

    def add_return_field(self, field: ReturnCustomField):
        try:
            self.return_fields.append(field)
            Log.debug("Added return field")
        except Exception as e:
            raise SaasException(f"Error adding return field: {e}")

    def change_password(self):
        Log.info("Changing password for Dell iDRAC Plugin user")

        admin_username = self.get_config("login")
        admin_password = self.get_config("password")
        idrac_ip = self.get_config("idrac_ip")

        if not all([admin_username, admin_password, idrac_ip]):
            raise SaasException('Missing required config fields: "login", "password", or "idrac_ip"')

        client = DelliDRACClient(admin_username, admin_password, idrac_ip, self.user)
        user_id = self.get_config("user_id") or client.get_user_id_from_user_fields()

        if not user_id:
            raise SaasException("Cannot determine user_id. Set it in config or user fields.")

        self.__user_id = user_id
        client.check_username_by_id(user_id)
        self._client = client

        new_password = self.user.new_password.value
        client.change_dell_idrac_user_password(user_id, new_password)

        self.add_return_field(ReturnCustomField(type="text", label="user_id", value=Secret(user_id)))
        Log.info("Password changed successfully.")

    def rollback_password(self):
        try:
            Log.debug("Rolling back password")
            old_password = self.user.prior_password.value[-1]
            self._client.change_dell_idrac_user_password(self.__user_id, old_password)
            Log.info("Password rolled back successfully.")
        except Exception as e:
            raise SaasException(f"Rollback failed: {e}")


class DelliDRACClient:
    def __init__(self, admin_username: str, admin_password: str, idrac_ip: str, user: SaasUser):
        self.__admin_username = admin_username
        self.__admin_password = admin_password
        self.__idrac_ip = idrac_ip
        self.__user = user

    def get_user_id_from_user_fields(self) -> str | None:
        for field in self.__user.fields:
            if field.label == "user_id" and field.values:
                return field.values[-1]

    def check_username_by_id(self, user_id: str):
        url = ACCOUNT_SERVICE_URL.format(idrac_ip=self.__idrac_ip,user_id=user_id)
        try:
            response = requests.get(url, auth=(self.__admin_username, self.__admin_password))
            if response.status_code == 200:
                username = response.json().get("UserName")
                if username != self.__user.username.value:
                    raise SaasException("Username mismatch with user_id")
            elif response.status_code == 404:
                raise SaasException("User not present in Dell iDRAC")
            else:
                raise SaasException(f"Unexpected error: {response.status_code}")
        except Exception as e:
            raise SaasException(f"Failed to verify user ID: {e}")

    def change_dell_idrac_user_password(self, user_id: str, password: str):
        url = ACCOUNT_SERVICE_URL.format(idrac_ip=self.__idrac_ip,user_id=user_id)
        payload = {"Password": password}
        try:
            response = requests.patch(url, json=payload, auth=(self.__admin_username, self.__admin_password))
            if response.status_code != 204:
                raise SaasException(f"Password rotation failed: {response.status_code} - {response.text}")
            Log.info("Password changed successfully")
        except Exception as e:
            raise SaasException(f"Password change request failed: {e}")