from __future__ import annotations
from typing import List, TYPE_CHECKING
from tempfile import NamedTemporaryFile
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from kdnrm.log import Log

try:
    import requests
except ImportError as exc:
    raise SaasException(
        'Missing required module: boto3. Please install it using "pip install requests"'
    ) from exc
if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):
    name = "Oracle Identity Domain User Plugin"

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
        self.__ocid = None
        self.temp_file = NamedTemporaryFile(suffix=".tok")

    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="identity_domain",
                label="Identity Domain",
                desc='Identity Domain for the Oracle Identity Domain User Plugin ended with ".identity.oraclecloud.com"',
                required=True,
            ),
        ]

    @property
    def can_rollback(self) -> bool:
        return True

    def add_return_field(self, field: ReturnCustomField):
        """
        Add a custom return field to the plugin.
        This method is used to add a custom field to the plugin's return fields.
        :param field: The custom field to be added.
        """
        Log.info("Adding return field to Oracle Identity Domain User Plugin")
        self.return_fields.append(field)
        Log.debug(f"Added return field: {field.label}")

    def change_password(self):
        """
        Change the password for the Oracle Identity Domain User Plugin user.
        This method connects to the Oracle Identity Domain User Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Oracle Identity Domain User Plugin")
        Log.debug("Checking required fields in config record")
        oracle_admin_record = self.config_record.dict.get("fields", [])
        identity_domain = self.get_config("identity_domain")
        token_file_ref = next(
            (
                field["value"][0]
                for field in oracle_admin_record
                if field["type"] == "fileRef"
            ),
            None,
        )
        Log.debug('Downloading "tokens.tok" file')
        self.config_record.download_file_by_title("tokens.tok", self.temp_file.name)
        if not token_file_ref:
            raise SaasException(
                "Missing 'fileRef' field in config record. \
                Please ensure the token file is provided."
            )
        with open(self.temp_file.name, "r", encoding="utf-8") as file:
            access_token = file.read().strip()
        self._client = OracleClient(
            access_token=access_token, identity_domain=identity_domain
        )
        self.__ocid = self._client.get_ocid_by_username(self.user.username.value)
        self._client.update_user_password(
            ocid=self.__ocid, new_password=self.user.new_password.value
        )
        self.add_return_field(
            ReturnCustomField(
                value=Secret(self.__ocid),
                label="Oracle Identity Domain User OCID",
                type="text",
            )
        )
        self.add_return_field(
            ReturnCustomField(
                value=Secret(identity_domain),
                label="Oracle Identity Domain",
                type="text",
            )
        )

    def rollback_password(self):
        """
        Rollback the password change for the Oracle Identity Domain User Plugin user.
        This method is called to revert the password change if needed.
        """
        Log.info("Rolling back password change for Oracle Identity Domain User Plugin")
        if self.__ocid is not None:
            old_password = self.user.prior_password.value[-1]
            self._client.update_user_password(ocid=self.__ocid, new_password=old_password)
        else:
            Log.error("OCID is not set, cannot rollback password change")
            raise SaasException("OCID is not set, cannot rollback password change")


class OracleClient:
    """
    A client for interacting with Oracle Identity Domain User Plugin API.
    """

    BASE_URL_TEMPLATE = "https://{domain}/admin/v1/Users"
    PATCH_OPERATION_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    CONTENT_SCIM_JSON = "application/scim+json"

    def __init__(self, identity_domain: str, access_token: str):
        self.__access_token = access_token
        self.__base_url = self.BASE_URL_TEMPLATE.format(domain=identity_domain)

    def __get_params(self, username):
        return {"filter": f'userName eq "{username}"'}

    def __get_header(self):
        return {
            "Authorization": f"Bearer {self.__access_token}",
            "Content-Type": self.CONTENT_SCIM_JSON,
        }

    def __get_payload_header(self, new_password):
        return {
            "schemas": [self.PATCH_OPERATION_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "password", "value": new_password}
            ],
        }

    def get_ocid_by_username(self, username: str):
        """
        Get the OCID of a user by their username.
        :param username: The username of the user.
        :return: The OCID of the user.
        """
        Log.info(f"Getting OCID for user: {username}")
        try:
            headers = self.__get_header()
            params = self.__get_params(username)
            response = requests.get(
                self.__base_url, headers=headers, params=params, timeout=10
            )
        except requests.RequestException as e:
            raise SaasException(f"Failed to get user by username: {str(e)}") from e
        if response.status_code == 200:
            resources = response.json().get("Resources")
            if not resources:
                raise SaasException(
                    f"User {username} not found in Oracle Identity Domain"
                )
            return resources[0].get("id")
        else:
            status_code_error_type_map = {
                400: "Bad request",
                401: "Unauthorized",
                404: "User not found",
                403: "Forbidden",
                500: "Internal server error",
            }
            msg = f"{response.reason or status_code_error_type_map.get(response.status_code)}, Status Code:{response.status_code}, Message: {response.text}"
            Log.error(msg=msg)
            raise SaasException(msg=response.reason or response.status_code)

    def update_user_password(self, ocid: str, new_password: str):
        """
        Update the password for a user by their OCID.
        :param user_id: The OCID of the user.
        """
        try:
            Log.info("Updating password for user")
            headers = self.__get_header()
            payload = self.__get_payload_header(new_password)
            response = requests.patch(
                f"{self.__base_url}/{ocid}", headers=headers, json=payload, timeout=10
            )
        except requests.RequestException as e:
            raise SaasException(f"Failed to update password: {str(e)}") from e
        if response.status_code == 200:
            Log.info("Password updated successfully")
        else:
            status_code_error_type_map = {
                400: "Bad request",
                401: "Unauthorized",
                404: "User not found",
                403: "Forbidden",
                500: "Internal server error",
            }
            msg = f"{response.reason or status_code_error_type_map.get(response.status_code)}, Status Code:{response.status_code}, Message: {response.text}"
            Log.error(msg=msg)
            raise SaasException(msg=response.reason or response.status_code)
