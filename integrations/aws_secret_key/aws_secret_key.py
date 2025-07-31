from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, SaasConfigItem, Secret

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
    from boto3 import Session


class SaasPlugin(SaasPluginBase):
    name = "AWS Secret Key"
    summary = "Rotate AWS access keys for IAM users."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self,
        user: SaasUser,
        config_record: Record,
        provider_config=None,
        force_fail=False
    ):
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None
        self._old_access_key_id = None
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="username",
                label="IAM Username",
                desc="AWS IAM username for which to rotate access keys.",
                required=True
            ),
            SaasConfigItem(
                id="client_id",
                label="Client ID",
                desc="AWS Access Key ID for authentication.",
                required=False
            ),
            SaasConfigItem(
                id="client_secret",
                label="Client Secret",
                desc="AWS Secret Access Key for authentication.",
                is_secret=True,
                type="secret",
                required=True
            ),
            SaasConfigItem(
                id="aws_region",
                label="AWS Region",
                desc="AWS Region. Required if not using a PAM AWS Configuration.",
                required=True
            ),
        ]

    @classmethod
    def requirements(cls) -> List[str]:
        return ["boto3"]

    @property
    def can_rollback(self) -> bool:
        return False

    def _validate_username(self, username: str) -> None:
        """Validate IAM username according to AWS rules."""
        if not username:
            raise SaasException("Username cannot be empty.")
        
        if len(username) < 1 or len(username) > 128:
            raise SaasException(
                "Username must be between 1 and 64 characters."
            )

        # AWS IAM username pattern: alphanumeric and +=,.@-_
        if not re.match(r'^[a-zA-Z0-9+=,.@\-_]+$', username):
            raise SaasException(
                "Username contains invalid characters. "
                "Only alphanumeric and +=,.@-_ are allowed."
            )

    def _validate_access_key_id(self, access_key_id: str) -> None:
        """Validate AWS Access Key ID format."""
        if not access_key_id:
            raise SaasException("Access Key ID cannot be empty.")
        
        if len(access_key_id) != 20:
            raise SaasException("Access Key ID must be exactly 20 characters.")
        
        if not access_key_id.startswith("AKIA"):
            raise SaasException("Access Key ID must start with 'AKIA'.")
        
        # Check if it contains only alphanumeric characters
        if not re.match(r'^AKIA[A-Z0-9]+$', access_key_id):
            raise SaasException("Access Key ID contains invalid characters.")

    def _validate_region(self, region: str) -> None:
        """Validate AWS region format."""
        if not region:
            raise SaasException("AWS region cannot be empty.")
        
        # AWS region pattern: us-east-1, eu-west-2, etc.
        if not re.match(r'^[a-z]+-[a-z]+-[0-9]+$', region):
            raise SaasException(
                f"Invalid AWS region format: {region}. "
                f"Expected format: us-east-1"
            )

    @property
    def aws_access_key_id(self) -> Optional[Secret]:
        access_key_id = self.get_config("client_id")
        if access_key_id is None and self.provider_config is not None:
            access_key_id = Secret.get_value(self.provider_config.aws_access_key_id)

        if access_key_id is not None:
            self._validate_access_key_id(str(access_key_id))
            return Secret(access_key_id)
        return None

    @property
    def aws_secret_access_key(self) -> Optional[Secret]:
        secret_access_key = self.get_config("client_secret")
        if secret_access_key is None and self.provider_config is not None:
            secret_access_key = Secret.get_value(self.provider_config.aws_secret_access_key)

        if secret_access_key is not None:
            return Secret(secret_access_key)
        return None

    @property
    def aws_region(self) -> str:
        region = self.get_config("aws_region")
        if region is None and self.provider_config is not None:
            region_names = Secret.get_value(
                self.provider_config.region_names
            )  # type: List
            if len(region_names) > 0:
                region = region_names[0]

        if region is None:
            raise SaasException(
                "The AWS Region is blank. Either set in the SaaS "
                "configuration record or allow plugin access to the "
                "PAM AWS Configuration record."
            )

        self._validate_region(region)
        return region

    @property
    def iam_username(self) -> str:
        username = self.get_config("username")
        if username is None:
            raise SaasException(
                "The IAM username is required for AWS secret key rotation."
            )

        self._validate_username(username)
        return username

    @staticmethod
    def _using_session() -> Optional[Session]:
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is not None:
            return session
        return None

    @property
    def client(self) -> Any:
        """Get the IAM client."""
        if self._client is None:
            aws_access_key_id = self.aws_access_key_id
            aws_secret_access_key = self.aws_secret_access_key
            aws_region = self.aws_region

            # If either access/secret are blank, check if we have attached role.
            if aws_access_key_id is None or aws_secret_access_key is None:
                Log.debug(
                    "aws access id and secret key are blank, checking session"
                )
                session = self._using_session()
                if session is not None:
                    Log.debug(
                        "a session exists, using it for IAM authentication"
                    )
                    self._client = session.client("iam", region_name=aws_region)
                else:
                    Log.error(
                        "either the aws access id or secret key is missing"
                    )
                    if aws_access_key_id is None:
                        raise SaasException(
                            "The AWS Access Key ID is blank. Either set in "
                            "the SaaS configuration record or allow plugin "
                            "access to the PAM AWS Configuration record."
                        )
                    if aws_secret_access_key is None:
                        raise SaasException(
                            "The AWS Secret Access Key is blank. Either set "
                            "in the SaaS configuration record or allow plugin "
                            "access to the PAM AWS Configuration record."
                        )

            # Else we have access/secret from the provider or config record.
            else:
                Log.debug(
                    "using aws access id and secret key from vault or "
                    "AWS PAM configuration"
                )
                self._client = boto3.client(
                    "iam",
                    aws_access_key_id=aws_access_key_id.value,
                    aws_secret_access_key=aws_secret_access_key.value,
                    region_name=aws_region
                )
        return self._client

    def _user_exists(self, username: str) -> bool:
        """Check if the IAM user exists."""
        try:
            self.client.get_user(UserName=username)
            return True
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                Log.error(f"Error checking if user exists: {err}")
                raise SaasException(
                    f"Error checking if user {username} exists."
                ) from err

    def _list_access_keys(self, username: str) -> List[Dict[str, Any]]:
        """List all access keys for the specified user."""
        try:
            response = self.client.list_access_keys(UserName=username)
            return response['AccessKeyMetadata']
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                Log.error(f"User {username} does not exist")
                raise SaasException(f"User {username} does not exist") from err
            elif err.response["Error"]["Code"] == "AccessDenied":
                Log.error(f"Access denied for user {username}: {err}")
                raise SaasException(
                    f"Access denied for user {username}."
                ) from err
            else:
                Log.error(
                    f"Error listing access keys for user {username}: {err}"
                )
                raise SaasException(
                    f"Could not list access keys for user {username}."
                ) from err

    def _create_access_key(self, username: str) -> Dict[str, str]:
        """Create a new access key for the specified user."""
        try:
            self._delete_access_key(username)
            # Create new access key
            response = self.client.create_access_key(UserName=username)
            access_key = response['AccessKey']
            return {
                'AccessKeyId': access_key['AccessKeyId'],
                'SecretAccessKey': access_key['SecretAccessKey']
            }
        except ClientError as err:
            if err.response["Error"]["Code"] == "LimitExceeded":
                Log.error(
                    f"access key limit exceeded for user {username}: {err}"
                )
                raise SaasException(
                    f"Access key limit exceeded for user {username}. "
                    f"Delete existing keys first."
                ) from err
            else:
                Log.error(f"error creating access key for user {username}: {err}")
                raise SaasException(
                    f"Could not create access key for user {username}."
                ) from err

    def _delete_access_key(self, username: str):
        """Delete the specified access key."""
        old_access_key_id = None
        try:
            keys_count = len(self._list_access_keys(username))
            if keys_count == 2:
                old_access_key_id = self._get_old_access_key_from_user_field()
                if old_access_key_id is None:
                    Log.debug(
                        f"User {username} has no old access key, no need to delete"
                    )
                    raise SaasException(
                        f"User {username} has no old access key, no need to delete"
                    )
                self.client.delete_access_key(
                    UserName=username, AccessKeyId=old_access_key_id
                )
                Log.info(
                    f"Successfully deleted access key {old_access_key_id} "
                    f"for user {username}"
                )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                Log.warning(
                    f"access key {old_access_key_id or 'unknown'} not found "
                    f"for user {username}"
                )
            elif err.response["Error"]["Code"] == "LimitExceeded":
                Log.error(
                    f"access key limit exceeded for user {username}: {err}"
                )
            elif err.response["Error"]["Code"] == "ServiceFailure":
                Log.error(f"service failure for user {username}: {err}")
                raise SaasException(
                    f"Service failure for user {username}."
                ) from err
            else:
                Log.error(
                    f"error deleting access key {old_access_key_id or 'unknown'} "
                    f"for user {username}: {err}"
                )
                raise SaasException(
                    f"Could not delete access key "
                    f"{old_access_key_id or 'unknown'} for user {username}."
                ) from err
        except Exception as err:
            Log.error(f"error deleting access key for user {username}")
            raise SaasException(f"Could not delete access key {err}") from err

    def _get_old_access_key_from_user_field(self) -> Optional[str]:
        """Extract the old access key ID from the user field."""
        for field in self.user.fields:
            if field.label == "aws_access_key_id":
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    return value[0] if value else None
                return value
        raise SaasException(
            "AWS Access Key ID is required in user fields",
            code="aws_access_key_id_required"
        )

    def add_return_field(self, field: ReturnCustomField):
        """Add a return field to be stored in PAM user record."""
        self.return_fields.append(field)

    def change_password(self):
        """Rotate the AWS access key - create new key and delete old one."""
        username = self.iam_username
        
        Log.info(f"Starting AWS access key rotation for user: {username}")
        
        # Check if user exists
        if not self._user_exists(username):
            raise SaasException(f"IAM user {username} does not exist.")
      
        Log.info(f"Creating new access key for user {username}")
        new_key_info = self._create_access_key(username)

        if hasattr(self.user, 'new_password'):
            # Store the new secret access key as the "new password"
            self.user.new_password = Secret(new_key_info['SecretAccessKey'])

        # Log success (be careful not to log sensitive information)
        Log.info(f"Successfully created new access key for user {username}")

        self.add_return_field(
            ReturnCustomField(
                label="aws_access_key_id",
                value=Secret(new_key_info['AccessKeyId'])
            )
        )
        self.add_return_field(
            ReturnCustomField(
                label="aws_secret_access_key",
                value=Secret(new_key_info['SecretAccessKey'])
            )
        )

        Log.debug(f"New access key ID: {new_key_info['AccessKeyId']}")

        Log.info("AWS access key rotation completed successfully")

    def rollback_password(self):
        """Rollback access key rotation (not supported)."""
        Log.info("Rollback is not supported")
