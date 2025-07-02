from __future__ import annotations
from typing import List, TYPE_CHECKING, Optional
import base64
import json

import requests
from requests.models import Response

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, SaasConfigItem, SaasUser, Secret

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
        self._user_sys_id = None
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

    def _initialize_client(self) -> ServiceNowClient:
        """Initialize ServiceNow client with config credentials."""
        Log.info("Retrieving ServiceNow admin credentials and instance URL from config record")

        admin_username = self.get_config("admin_user")
        admin_password = self.get_config("admin_password")
        instance_url = self.get_config("servicenow_url")

        if not all([admin_username, admin_password, instance_url]):
            raise SaasException(
                "Admin credentials or ServiceNow instance URL are not configured."
            )

        return ServiceNowClient(
            admin_user=admin_username,
            admin_password=admin_password,
            instance_url=instance_url,
            user=self.user,
        )

    def _get_user_sys_id(self, client: ServiceNowClient) -> str:
        """Get the sys_id for the user."""
        sys_id = client.get_sys_id_for_user()
        if not sys_id:
            raise SaasException("Could not determine user sys_id.")
        return sys_id

    def change_password(self):
        """Change password for ServiceNow user."""
        Log.info("Changing password for ServiceNow Plugin user")

        try:
            self._client = self._initialize_client()
            self._user_sys_id = self._get_user_sys_id(self._client)
            new_password = self.user.new_password.value  # type: ignore

            self._client.change_user_password(self._user_sys_id, new_password)
            self._add_return_fields()
            Log.info("Password changed successfully.")

        except SaasException:
            raise
        except Exception as e:
            Log.error(f"Unexpected error during password change: {e}")
            raise SaasException(f"Password change failed: {e}") from e

    def _add_return_fields(self):
        """Add return fields for successful password change."""
        if self._user_sys_id:
            self.add_return_field(
                ReturnCustomField(
                    type="text",
                    label="user_sys_id",
                    value=Secret(self._user_sys_id)
                )
            )

        instance_url = self.get_config("servicenow_url")
        if instance_url:
            self.add_return_field(
                ReturnCustomField(
                    type="url",
                    label="instance_url",
                    value=Secret(instance_url)
                )
            )

    def rollback_password(self):
        """Rollback password to previous value."""
        if self.user.prior_password is None:
            raise SaasException(
                "There is no current password. Cannot rotate back to prior password."
            )

        if not self._user_sys_id or not self._client:
            raise SaasException("User sys_id or client is not set. Cannot roll back password.")

        Log.debug("Rolling back password")
        try:
            old_password = self.user.prior_password.value  # type: ignore
            self._client.change_user_password(self._user_sys_id, old_password)
            Log.info("Password rolled back successfully.")
        except Exception as e:
            Log.error(f"Failed to rollback password: {e}")
            raise SaasException(f"Password rollback failed: {e}") from e


class ServiceNowClient:
    """Client for interacting with ServiceNow REST API to manage user accounts."""

    # Constants
    API_TIMEOUT = 30
    USER_TABLE_ENDPOINT = "/api/now/table/sys_user"

    def __init__(
        self,
        admin_user: str,
        admin_password: str,
        instance_url: str,
        user: SaasUser
    ):
        self._admin_user = admin_user
        self._admin_password = admin_password
        self._instance_url = instance_url.rstrip("/")
        self._user = user

    @property
    def _auth_header(self) -> dict:
        """Build Basic Authentication header."""
        credentials = f"{self._admin_user}:{self._admin_password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    @property
    def _default_headers(self) -> dict:
        """Get default headers for ServiceNow API requests."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._auth_header,
        }

    def _build_user_table_url(self, endpoint_path: str = "") -> str:
        """Build URL for user table API endpoint."""
        base_url = f"{self._instance_url}{self.USER_TABLE_ENDPOINT}"
        return f"{base_url}{endpoint_path}" if endpoint_path else base_url

    def _make_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        **kwargs
    ) -> Response:
        """Make HTTP request with error handling."""
        if headers is None:
            headers = self._default_headers

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.API_TIMEOUT,
                **kwargs
            )
            return response
        except requests.RequestException as e:
            Log.error(f"Request failed: {e}")
            raise SaasException(f"API request failed: {e}") from e

    def _handle_error_response(self, response: Response) -> None:
        """Handle error response codes from ServiceNow API."""
        status_code_messages = {
            400: "Bad request",
            401: "Unauthorized - check admin credentials",
            403: "Forbidden - insufficient permissions",
            404: "Not found",
            500: "Internal server error",
        }

        error_type = status_code_messages.get(
            response.status_code,
            "Unknown error"
        )

        try:
            error_data = response.json()
            if "error" in error_data:
                error_detail = error_data["error"]
                msg_text = error_detail.get("message", "")
                detail_text = error_detail.get("detail", "")
                detailed_message = f"{msg_text}. {detail_text}".strip(". ")
            else:
                detailed_message = str(error_data)
        except (ValueError, json.JSONDecodeError):
            detailed_message = response.text or "No error details"

        error_msg = (
            f"{error_type} (Status {response.status_code}): {detailed_message}"
        )

        Log.error(error_msg)
        raise SaasException(error_msg)

    def get_sys_id_for_user(self) -> str:
        """Get the ServiceNow sys_id for the given username."""
        Log.info("Fetching sys_id for user in ServiceNow")

        username = self._user.username.value
        url = self._build_user_table_url(f"?user_name={username}")

        Log.debug(f"ServiceNow API URL: {url}")

        response = self._make_request("GET", url)

        if response.status_code == 200:
            data = response.json().get("result", [])
            if not data:
                raise SaasException(f"User '{username}' not found in ServiceNow.")
            sys_id = data[0].get("sys_id")
            if not sys_id:
                raise SaasException(f"No sys_id found for user '{username}'.")
            return sys_id

        self._handle_error_response(response)
        return ""

    def change_user_password(self, sys_id: str, new_password: str) -> None:
        """Change the password for the user identified by sys_id."""
        Log.info(f"Changing password for user with sys_id: {sys_id}")

        url = self._build_user_table_url(f"/{sys_id}?sysparm_input_display_value=true")
        payload = {
            "user_password": new_password,
            "password_needs_reset": "false"
        }

        response = self._make_request("PATCH", url, **{"json": payload})

        if response.status_code == 200:
            Log.info("Password changed successfully.")
        else:
            self._handle_error_response(response)
