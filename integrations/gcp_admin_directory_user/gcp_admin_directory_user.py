from __future__ import annotations
from typing import List, TYPE_CHECKING
from tempfile import NamedTemporaryFile
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except ImportError as exc:
    raise SaasException(
        'Missing required modules: Please install it using "pip install -r requirements_test.txt"'
    ) from exc
if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

LOGIN_URL = "https://console.cloud.google.com/"
SERVICE_ACCOUNT_JSON_FILE = "service_account.json"

class SaasPlugin(SaasPluginBase):
    name = "GCP Admin Directory User Plugin"
    summary = "Change a user password in GCP Admin Directory."
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
        self.temp_file = NamedTemporaryFile(suffix=".json")
        self._can_rollback = False
        self._client = None
        self.return_fields = []

    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="admin_email",
                label="Admin Email",
                desc='Email address of the administrator with User Management permissions',
                required=True,
            ),
        ]

    @property
    def can_rollback(self) -> bool:
        return self._can_rollback
    @can_rollback.setter
    def can_rollback(self, value: bool):
        self._can_rollback = value
    def add_return_field(self, field: ReturnCustomField):
        """
        Add a custom return field to the plugin.
        This method is used to add a custom field to the plugin's return fields.
        :param field: The custom field to be added.
        """
        Log.info("Adding return field to GCP Admin Directory User Plugin")
        self.return_fields.append(field)
        Log.debug("Added return field")

    def change_password(self):
        """
        Change the password for the GCP Admin Directory User Plugin user.
        This method connects to the GCP Admin Directory User Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for GCP Admin Directory User Plugin")
        Log.debug("Checking required fields in config record")
        gcp_admin_record = self.config_record.dict.get("fields", []) # type: ignore
        admin_email = self.get_config("admin_email")
        if not admin_email:
            raise SaasException(
                "Missing 'admin_email' field in config record. \
                Please ensure the admin email is provided."
            )
        token_file_repo = next(
            (
                field["value"][0]
                for field in gcp_admin_record
                if field["type"] == "fileRef"
            ),
            None,
        )
        if not token_file_repo:
            raise SaasException(
                "Missing 'fileRef' field in config record. \
                Please ensure the token file is provided."
            )
        Log.debug(f'Downloading "{SERVICE_ACCOUNT_JSON_FILE}" file')
        self.config_record.download_file_by_title(
            SERVICE_ACCOUNT_JSON_FILE, self.temp_file.name
        )
        try:
            self._client = GCPClient(admin_email=admin_email, service_account_json=self.temp_file.name)
            self.can_rollback = True
        except SaasException as e:
            self._client = None
            self.can_rollback = False
            Log.error(f"Failed to initialize GCP client: {str(e)}")
            raise SaasException(f"Failed to initialize GCP client: {str(e)}") from e
        user_email = self.user.username.value
        new_password = self.user.new_password.value # type: ignore
        if not user_email or not new_password:
            raise SaasException(
                "Missing 'username' or 'new_password' field in user. \
                Please ensure both fields are provided."
            )
        self._client.update_user_password(
            user_email=user_email,
            new_password=new_password,
        )
        self.add_return_field(
            ReturnCustomField(
                value=Secret(LOGIN_URL),
                label="Login URL",
                type="url"
            )
        )

    def rollback_password(self):
        """
        Rollback the password change for the GCP Admin Directory User Plugin user.
        This method is called to revert the password change if needed.
        """
        Log.info("Rolling back password change for GCP Admin Directory User Plugin")
        try:
            if self._client:
                user_email = self.user.username.value
                if not user_email:
                    raise SaasException(
                        "Missing 'username'field in user."
                    )
                self._client.update_user_password(
                    user_email=user_email,
                    new_password= self.user.prior_password.value[-1], # type: ignore
                )
            else:
                raise SaasException("Client not initialized")
        except SaasException as e:
            Log.error(f"Failed to rollback password change: {str(e)}")
            raise SaasException(f"Failed to rollback password change: {str(e)}") from e

class GCPClient:
    """
    A client for interacting with GCP Admin Directory User Plugin API.
    """
    SCOPES = ['https://www.googleapis.com/auth/admin.directory.user']
    def __init__(self, admin_email: str, service_account_json):
        self.__admin_email = admin_email
        self.__service_account_json = service_account_json
    def update_user_password(self, user_email: str, new_password: str):
        """
        Change the password for a user by their user_email.
        :param user_email: The email of the user.
        :param new_password: The new password to set for the user.
        """
        try:
            credentials = service_account.Credentials.from_service_account_file(
            self.__service_account_json, scopes=self.SCOPES
            )
            delegated_credentials = credentials.with_subject(self.__admin_email)
            service = build('admin', 'directory_v1', credentials=delegated_credentials)
            body = {
                "password": new_password,
                "changePasswordAtNextLogin": False
            }
            service.users().update(  # pylint: disable=maybe-no-member
                userKey=user_email,
                body=body
            ).execute()
        except Exception as e:
            Log.error(f"Failed to change password for user {user_email}: {str(e)}")
            raise SaasException(f"Failed to change password: {str(e)}") from e