from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from pysnc import ServiceNowClient
from typing import List, Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):

    name = "ServiceNow User Plugin"
    summary = "Change user password in ServiceNow."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self,
                 user: SaasUser,
                 config_record: Record,
                 provider_config: Any = None,
                 force_fail: bool = False):

        super().__init__(user, config_record, provider_config, force_fail)

        self._client = None
        self._user_sys_id = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["pysnc"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="admin_username",
                label="Admin Username",
                desc="ServiceNow administrator username.",
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="admin_password",
                label="Admin Password",
                desc="Password for the ServiceNow administrator.",
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="instance_name",
                label="Instance Name",
                desc="ServiceNow instance name (e.g., 'dev12345' for "
                     "dev12345.service-now.com).",
                is_secret=False,
                required=True,
            ),
        ]

    @property
    def client(self) -> ServiceNowClient:
        if self._client is None:
            Log.debug("initializing ServiceNow client")
            
            admin_username = self.get_config("admin_username")
            admin_password = self.get_config("admin_password")
            instance_name = self.get_config("instance_name")
            
            if not all([admin_username, admin_password, instance_name]):
                raise SaasException("Admin credentials or instance name are "
                                    "not configured.")
            
            self._client = ServiceNowClient(instance_name, 
                                            auth=(admin_username, admin_password))
            
        return self._client

    @property
    def user_sys_id(self):
        if self._user_sys_id is None:
            Log.debug("getting user sys_id")

            gr = self.client.GlideRecord("sys_user")
            if gr.get("user_name", self.user.username.value):
                self._user_sys_id = gr.get_value("sys_id")
            else:
                raise SaasException(f"User '{self.user.username.value}' not "
                                    f"found in ServiceNow.")
      
        return self._user_sys_id

    @property
    def can_rollback(self) -> bool:
        # ServiceNow allows password rollback
        return True

    def update_password(self, password: Secret):
        """
        Update the password for the ServiceNow User Plugin user.
        This method connects to the ServiceNow instance using the admin 
        credentials and changes the password for the specified user.
        """
        Log.debug("updating the password")
        
        instance_name = self.get_config("instance_name")
        url = (f"https://{instance_name}.service-now.com/api/now/table/"
               f"sys_user/{self.user_sys_id}")
        params = {"sysparm_input_display_value": "true"}
        data = {
            "user_password": password.value,
            "password_needs_reset": "false"
        }

        try:
            response = self.client.session.patch(url, json=data, params=params)
            if response.status_code == 200:
                Log.debug("password updated successfully")
            else:
                Log.error(f"failed to update password: {response.status_code} "
                          f"- {response.text}")
                raise SaasException(f"Failed to update password: "
                                    f"{response.status_code} - {response.text}")
        except Exception as err:
            Log.error(f"could not change password: {err}")
            raise SaasException(f"Could not change password: {err}") from err

    def change_password(self):
        """
        Change the password for the ServiceNow User Plugin user.
        This method connects to the ServiceNow instance using the admin 
        credentials and changes the password for the specified user.
        """
        Log.info("Changing password for ServiceNow User Plugin")
        if self.user.new_password is None:
            raise SaasException("New password is not set.")
        self.update_password(password=self.user.new_password)
        Log.info("password rotate was successful")

    def rollback_password(self):
        """
        Rollback the password change for the ServiceNow User Plugin user.
        This method is called to revert the password change if needed.
        """

        if self.user.prior_password is None:
            raise SaasException("Cannot rollback password. The current "
                                "password is not set.")

        Log.info("Rolling back password change for ServiceNow User Plugin")
        # Assert helps type checker understand prior_password is not None
        assert self.user.prior_password is not None
        self.update_password(password=self.user.prior_password)
        Log.info("rolling back password was successful")
