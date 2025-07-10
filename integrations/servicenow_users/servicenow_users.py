from __future__ import annotations
from typing import List, Any, TYPE_CHECKING
from pysnc import ServiceNowClient
from pysnc.exceptions import (
    AuthenticationException,
    NoRecordException,
    UpdateException,
    RequestException,
    RestException,
    InstanceException,
    NotFoundException
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

    # ServiceNow API Constants
    SERVICENOW_BASE_URL = "https://{instance}.service-now.com"
    SERVICENOW_USER_API_ENDPOINT = "/api/now/table/sys_user"
    SERVICENOW_USER_TABLE = "sys_user"
    API_TIMEOUT = 30

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
                type="hidden",
                required=True,
            ),
            SaasConfigItem(
                id="instance_name",
                label="Instance Name",
                desc="ServiceNow instance name (e.g., 'customer1' for "
                     "customer1.service-now.com).",
                is_secret=False,
                required=True,
            ),
        ]

    @property
    def client(self) -> ServiceNowClient:
        """
        Get the ServiceNow client.
        This method creates a new ServiceNowClient instance with the provided 
        credentials and returns it.
        """
        if self._client is None:
            Log.debug("initializing ServiceNow client")

            admin_username = self.get_config("admin_username")
            admin_password = self.get_config("admin_password")
            instance_name = self.get_config("instance_name")

            def _create_client():
                return ServiceNowClient(
                    instance=instance_name,
                    auth=(admin_username, admin_password)
                )

            try:
                self._client = self._handle_servicenow_exceptions(_create_client)
            except SaasException:
                # Re-raise SaasException as is
                raise
            except Exception as err:
                Log.error(f"Unexpected error initializing client: {err}")
                raise SaasException(f"Unexpected error initializing client: {err}") from err

        return self._client

    @property
    def user_sys_id(self):
        """
        Get the sys_id for the ServiceNow User Plugin user.
        
        This method connects to the ServiceNow instance using the admin 
        credentials and retrieves the sys_id for the specified user.
        """
        if self._user_sys_id is None:
            Log.debug("getting user sys_id")
            
            def _get_user_sys_id():
                gr = self.client.GlideRecord("sys_user")
                if gr.get("user_name", self.user.username.value):
                    return gr.get_value("sys_id")
                else:
                    raise SaasException(f"User '{self.user.username.value}' not found in ServiceNow.")

            try:
                self._user_sys_id = self._handle_servicenow_exceptions(_get_user_sys_id)
            except SaasException:
                # Re-raise SaasException as is
                raise
            except Exception as err:
                Log.error(f"Unexpected error getting user sys_id: {err}")
                raise SaasException(f"Unexpected error getting user sys_id: {err}") from err

        return self._user_sys_id

    def _build_user_api_url(self, sys_id: str) -> str:
        """Build the ServiceNow user API URL for a specific user."""
        instance_name = self.get_config("instance_name")
        base_url = self.SERVICENOW_BASE_URL.format(instance=instance_name)
        return f"{base_url}{self.SERVICENOW_USER_API_ENDPOINT}/{sys_id}"

    def _extract_servicenow_error_message(self, exception) -> str:
        """Extract clean error message from ServiceNow exception."""
        try:
            error_data = exception.args[0] if exception.args else {}

            if isinstance(error_data, dict):
                if 'error' in error_data:
                    error_info = error_data['error']
                    message = error_info.get('message', 'Unknown error')
                    detail = error_info.get('detail', '')
                    if detail:
                        return f"Message: '{message}', Detail: '{detail}'"
                    else:
                        return f"Message: '{message}'"

                elif 'message' in error_data:
                    message = error_data.get('message', 'Unknown error')
                    detail = error_data.get('detail', '')
                    if detail:
                        return f"Message: '{message}', Detail: '{detail}'"
                    else:
                        return f"Message: '{message}'"

                else:
                    return str(error_data)
            else:
                return str(error_data)

        except Exception:
            # Fallback to string representation if parsing fails
            return str(exception)

    def _handle_servicenow_exceptions(self, func, *args, **kwargs):
        """
        Universal exception handler for ServiceNow operations.
        
        This function wraps any ServiceNow operation and handles all possible
        ServiceNow exceptions in a consistent way.
        """
        try:
            return func(*args, **kwargs)
        except AuthenticationException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"AuthenticationException: {error_message}")
            raise SaasException(f"AuthenticationException: {error_message}") from err
        except NoRecordException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"NoRecordException: {error_message}")
            raise SaasException(f"NoRecordException: {error_message}") from err
        except UpdateException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"UpdateException: {error_message}")
            raise SaasException(f"UpdateException: {error_message}") from err
        except RequestException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"RequestException: {error_message}")
            raise SaasException(f"RequestException: {error_message}") from err
        except RestException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"RestException: {error_message}")
            raise SaasException(f"RestException: {error_message}") from err
        except InstanceException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"InstanceException: {error_message}")
            raise SaasException(f"InstanceException: {error_message}") from err
        except NotFoundException as err:
            error_message = self._extract_servicenow_error_message(err)
            Log.error(f"NotFoundException: {error_message}")
            raise SaasException(f"NotFoundException: {error_message}") from err

    @property
    def can_rollback(self) -> bool:
        """Check if rollback is currently enabled."""
        return True

    def update_password(self, password: Secret):
        """
        Update the password for the ServiceNow User Plugin user.
        
        This method connects to the ServiceNow instance using the admin 
        credentials and changes the password for the specified user.
        """
        Log.debug("updating the password")
        url = self._build_user_api_url(self.user_sys_id)
        params = {"sysparm_input_display_value": "true"}
        data = {
            "user_password": password.value,
            "password_needs_reset": "false"
        }

        def _update_password():
            response = self.client.session.patch(
                url,
                json=data,
                params=params,
                timeout=self.API_TIMEOUT
            )
            if response.status_code == 200:
                Log.debug("password updated successfully")
            return response

        try:
            self._handle_servicenow_exceptions(_update_password)
        except SaasException:
            raise
        except Exception as err:
            Log.error(f"Unexpected error updating password: {err}")
            raise SaasException(f"Unexpected error updating password: {err}") from err

    def change_password(self):
        """
        Change the password for the ServiceNow User Plugin user.
        
        This method connects to the ServiceNow instance using the admin 
        credentials and changes the password for the specified user.
        """
        Log.info("Changing password for ServiceNow User Plugin")

        if self.user.new_password is None:
            raise SaasException("New password is not set.")

        try:
            # Attempt password update
            self.update_password(password=self.user.new_password)
            Log.info("password rotate was successful")

        except Exception as err:
            Log.error(f"Exception details: {err}")
            raise

    def rollback_password(self):
        """
        Rollback the password change for the ServiceNow User Plugin user.
        
        This method is called to revert the password change if needed.
        """

        if self.user.prior_password is None:
            raise SaasException("Cannot rollback password. The current "
                                "password is not set.")

        Log.info("Rolling back password change for ServiceNow User Plugin")
        self.update_password(password=self.user.prior_password)
        Log.info("rolling back password was successful")
