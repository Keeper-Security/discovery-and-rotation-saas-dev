from __future__ import annotations
import json
from typing import List, Any, TYPE_CHECKING

import requests
from pysnc import ServiceNowClient
from pysnc.exceptions import (
    AuthenticationException,
    InstanceException,
    NotFoundException,
    RequestException,
    RestException
)
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from kdnrm.log import Log

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):

    name = "ServiceNow User"
    summary = "Change user password in ServiceNow"
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    # Constants
    BASE_URL = "https://{instance}.service-now.com"
    USER_API_PATH = "/api/now/table/sys_user"
    TIMEOUT = 30

    def __init__(self, user: SaasUser, config_record: Record,
                 provider_config: Any = None, force_fail: bool = False):
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None
        self._user_sys_id = None
        self.__rollback_password = False

    @classmethod
    def requirements(cls) -> List[str]:
        """Return the list of required Python packages."""
        return ["pysnc"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        """Return the configuration schema for the plugin."""
        return [
            SaasConfigItem(
                id="admin_username",
                label="Admin Username",
                desc="ServiceNow administrator username.",
                required=True
            ),
            SaasConfigItem(
                id="admin_password",
                label="Admin Password",
                desc="Password for the ServiceNow administrator.",
                is_secret=True,
                type="secret",
                required=True
            ),
            SaasConfigItem(
                id="instance_name",
                label="Instance Name",
                desc="ServiceNow instance name (e.g., 'customer1' for "
                     "customer1.service-now.com).",
                is_secret=False,
                required=True
            ),
        ]

    @property
    def client(self) -> ServiceNowClient:
        """Get or create the ServiceNow client."""
        if self._client is None:
            Log.debug("initializing ServiceNow client")
            self._client = ServiceNowClient(
                instance=self.get_config("instance_name"),
                auth=(
                    self.get_config("admin_username"),
                    self.get_config("admin_password")
                )
            )
        return self._client

    @property
    def user_sys_id(self):
        """Get the user system ID from ServiceNow."""
        try:
            if self._user_sys_id is None:
                Log.debug("getting user sys_id")
                gr = self.client.GlideRecord("sys_user")
                if gr.get("user_name", self.user.username.value):
                    self._user_sys_id = gr.get_value("sys_id")
                else:
                    Log.error(f"User '{self.user.username.value}' not found in ServiceNow.")
                    raise NotFoundException(
                        f"User '{self.user.username.value}' not found in "
                        f"ServiceNow."
                    )
            return self._user_sys_id
        except AuthenticationException as err:
            Log.error(f"authentication failed: {err}")
            raise SaasException(f"Authentication failed: {err}") from err
        except InstanceException as err:
            Log.error(f"instance exception: {err}")
            raise SaasException(f"Instance exception: {err}") from err
        except NotFoundException as err:
            Log.error(f"User Not Found Exception: {err}")
            raise SaasException(
                f"User '{self.user.username.value}' not found in ServiceNow."
            ) from err
        except RequestException as err:
            Log.error(f"request exception: {err}")
            raise SaasException(f"Request exception: {err}") from err
        except RestException as err:
            Log.error(f"rest exception: {err}")
            raise SaasException(f"Rest exception: {err}") from err
        except Exception as err:
            Log.error(f"could not get user sys_id: {err}")
            raise SaasException(
                f"Could not get user sys_id, received the following error: "
                f"{err}"
            ) from err

    @property
    def can_rollback(self) -> bool:
        """Check if password rollback is enabled."""
        return self.__rollback_password

    @can_rollback.setter
    def can_rollback(self, rollback_password: bool):
        """Set password rollback state."""
        self.__rollback_password = rollback_password

    def _get_user_url(self) -> str:
        """Build user API URL."""
        base = self.BASE_URL.format(
            instance=self.get_config("instance_name")
        )
        return f"{base}{self.USER_API_PATH}/{self.user_sys_id}"

    def error_handling(self, response: requests.Response) -> str:
        """Parse error response from ServiceNow."""
        error_detail = response.json()
        try:
            error_data = error_detail["error"]
            message = error_data.get("message", "Unknown error")
            detail = error_data.get("detail", "")
            error_detail = f"{message}: {detail}" if detail else message
        except (json.JSONDecodeError, KeyError):
            pass
        return error_detail

    def update_password(self, password: Secret):
        """Update the password for the ServiceNow User Plugin user.
        
        This method connects to the ServiceNow User Plugin account using 
        the admin credentials and changes the password for the specified user.
        """
        Log.debug("updating the password")
        try:
            response = self.client.session.patch(
                self._get_user_url(),
                json={
                    "user_password": password.value,
                    "password_needs_reset": "false"
                },
                params={"sysparm_input_display_value": "true"},
                timeout=self.TIMEOUT
            )

            if response.status_code == 200:
                Log.debug("password updated successfully")
                return

            error_detail = self.error_handling(response)
            if response.status_code == 403:
                Log.error(f"Forbidden: {error_detail}")
                raise SaasException(f"{error_detail}")
            else:
                self.can_rollback = True
                raise SaasException(
                    f"{response.status_code}: {error_detail}"
                )

        except Exception as err:
            Log.error(f"{err}")
            raise SaasException(
                f"Could not change password, received the following error: "
                f"{err}"
            ) from err

    def change_password(self):
        """Change the password for the ServiceNow User Plugin user."""
        if self.user.new_password is None:
            raise SaasException("New password is not set.")

        Log.info("Changing password for ServiceNow User Plugin")
        self.update_password(password=self.user.new_password)
        Log.info("password rotate was successful")

    def rollback_password(self):
        """Rollback the password change for the ServiceNow User Plugin user."""
        if self.user.prior_password is None:
            raise SaasException(
                "Cannot rollback password. The current password is not set."
            )

        Log.info("Rolling back password change for ServiceNow User Plugin")
        self.update_password(password=self.user.prior_password)
        Log.info("rolling back password was successful")
