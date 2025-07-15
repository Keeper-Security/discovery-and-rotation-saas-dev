from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem, ReturnCustomField
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from tempfile import NamedTemporaryFile
import json
import os
from typing import List, Any, TYPE_CHECKING
from google.cloud import iam_admin_v1
from google.oauth2 import service_account


if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'

class SaasPlugin(SaasPluginBase):

    name = "GCP Service Account"
    summary = "Create and manage service account keys in Google Cloud Platform."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self,
                 user: SaasUser,
                 config_record: Record,
                 provider_config: Any = None,
                 force_fail: bool = False):

        super().__init__(user, config_record, provider_config, force_fail)

        self._project_id = None
        self._service_account_email = None
        self._created_key_name = None
        self._iam_client = None
        
        # Create temporary file for storing the service account file
        self.temp_file = NamedTemporaryFile(suffix=".json", delete=False)
        self.temp_service_account_file = self.temp_file.name

    @classmethod
    def requirements(cls) -> List[str]:
        return ["google-cloud-iam"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        # No configuration fields needed - the plugin will automatically
        # detect and use attached JSON files from the record
        return []

    @property
    def project_id(self):
        if self._project_id is None:
            self._parse_service_account_file()
        return self._project_id

    @property
    def service_account_email(self):
        if self._service_account_email is None:
            self._parse_service_account_file()
        return self._service_account_email

    @property
    def iam_client(self):
        if self._iam_client is None:
            self._setup_iam_client()
        return self._iam_client


    def _parse_service_account_file(self):
        """Parse the service account file and extract project and service account information."""
        try:
            Log.debug("Downloading and parsing service account file")

            if not hasattr(self.config_record, 'files') or not self.config_record.files:
                raise SaasException("No files attached to the record.")
            
            # Find the first JSON file or any file (assuming it's the service account file)
            target_file = None
            for file_info in self.config_record.files:
                Log.debug(f"Found file: {file_info.name} (type: {getattr(file_info, 'type', 'unknown')})")
                if file_info.name.endswith('.json') or len(self.config_record.files) == 1:
                    target_file = file_info
                    break
            
            if target_file is None:
                # If no JSON file found, take the first file
                target_file = self.config_record.files[0]
            
            Log.debug(f"Using file: {target_file.name}")
            
            # Download the service account file
            self.config_record.download_file_by_title(target_file.name, self.temp_service_account_file)
            
            # Read and parse the downloaded file
            with open(self.temp_service_account_file, 'r', encoding='utf-8') as f:
                service_account_data = json.load(f)
            
            # Validate required fields
            required_fields = ["type", "project_id", "private_key_id", "private_key", "client_email"]
            for field in required_fields:
                if field not in service_account_data:
                    raise SaasException(f"Missing required field '{field}' in service account file.")
            
            if service_account_data.get("type") != "service_account":
                raise SaasException("The provided file is not a valid service account file.")
            
            self._project_id = service_account_data["project_id"]
            self._service_account_email = service_account_data["client_email"]
            
            Log.debug(f"Service account file parsed successfully. Project ID: {self._project_id}, Service Account: {self._service_account_email}")
            
        except json.JSONDecodeError as e:
            raise SaasException(f"Invalid JSON in service account file: {str(e)}") from e
        except FileNotFoundError as e:
            raise SaasException("Service account file not found. Please ensure a valid service account file is attached.") from e
        except Exception as e:
            raise SaasException(f"Failed to parse service account file: {str(e)}") from e

    def _setup_iam_client(self):
        """Setup the Google Cloud IAM client."""
        try:
            Log.debug("Setting up Google Cloud IAM client")
            
            # Ensure the service account file is created
            if not os.path.exists(self.temp_service_account_file):
                self._parse_service_account_file()
            
            # Create credentials from the service account file
            credentials = service_account.Credentials.from_service_account_file(
                self.temp_service_account_file,
                scopes=[CLOUD_PLATFORM_SCOPE]
            )
            
            # Create IAM client
            self._iam_client = iam_admin_v1.IAMClient(credentials=credentials)
            
            Log.debug("IAM client created successfully")
            
        except Exception as e:
            raise SaasException(f"Failed to setup IAM client: {str(e)}")

    @property
    def can_rollback(self) -> bool:
        """
        Check if rollback is possible.
        For this plugin, rollback is always possible if we have a created key to delete.
        """
        return False

    def _create_service_account_key(self):
        """Create a new service account key.""" 
        try:
            Log.info(f"Creating new service account key for {self.service_account_email}")
            
            # Prepare the request
            request = iam_admin_v1.CreateServiceAccountKeyRequest()
            request.name = f"projects/{self.project_id}/serviceAccounts/{self.service_account_email}"
            request.key_algorithm = iam_admin_v1.ServiceAccountKeyAlgorithm.KEY_ALG_RSA_2048
            request.private_key_type = iam_admin_v1.ServiceAccountPrivateKeyType.TYPE_GOOGLE_CREDENTIALS_FILE
            
            # Create the service account key
            key = self.iam_client.create_service_account_key(request=request)
            if isinstance(key.private_key_data, bytes):
                key_data = key.private_key_data.decode('utf-8')
            else:
                key_data = key.private_key_data
            
            self.add_return_field(
                ReturnCustomField(
                    label="GCP Service Account Key",
                    value=Secret(key_data)
                )
            )
            
            self._created_key_name = key.name
            
            Log.info(f"Successfully created service account key: {key.name}")
            
        except Exception as e:
            Log.error(f"Failed to create service account key: {str(e)}")
            raise SaasException(f"Could not create service account key: {str(e)}")

    def _delete_service_account_key(self, key_name: str):
        """Delete a specific service account key."""
        try:
            Log.info(f"Deleting service account key: {key_name}")
            
            # Prepare the request
            request = iam_admin_v1.DeleteServiceAccountKeyRequest()
            request.name = key_name
            
            # Delete the key
            self.iam_client.delete_service_account_key(request=request)
            
            Log.info(f"Successfully deleted service account key: {key_name}")
            
        except Exception as e:
            Log.error(f"Failed to delete service account key: {str(e)}")
            raise SaasException(f"Could not delete service account key: {str(e)}")

    def change_password(self):
        """
        Create a new service account key.
        In the context of this plugin, creating a new key represents "changing the password".
        """
        Log.info("Creating new service account key for GCP Service Account")
        
        try:
            # Create new service account key
            self._create_service_account_key()
            
            Log.info("Service account key creation was successful")
            
        except Exception as e:
            Log.error(f"Failed to create service account key: {str(e)}")
            raise

    def rollback_password(self):
        """
        Delete the previously created service account key.
        This method is called to revert the key creation if needed.
        """
        if self._created_key_name is None:
            raise SaasException("Cannot rollback. No service account key was created to delete.")

        Log.info("Rolling back service account key creation by deleting the created key")
        
        try:
            Log.info("Service account rollback is not supported")
            # TODO: Implement rollback after the file is uploaded to the record, will restore the old key if any error occurs
            pass
            
        except Exception as e:
            Log.error(f"Failed to rollback service account key: {str(e)}")
            raise

    def __del__(self):
        """Cleanup temporary file when plugin is destroyed."""
        if hasattr(self, 'temp_file'):
            try:
                self.temp_file.close()
                if os.path.exists(self.temp_service_account_file):
                    os.unlink(self.temp_service_account_file)
            except Exception:
                pass  # Ignore cleanup errors
