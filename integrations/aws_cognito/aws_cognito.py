from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from botocore.exceptions import ClientError
from typing import List, Optional, TYPE_CHECKING
from kdnrm.log import Log
import boto3

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
    from boto3 import Session


class SaasPlugin(SaasPluginBase):
    name = "AWS Cognito"
    summary = "Change a users password in AWS Cognito."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="user_pool_id",
                label="User Pool ID",
                desc="User Pool ID.",
                type="secret",
                required=True
            ),
            SaasConfigItem(
                id="aws_access_key_id",
                label="AWS Access Key ID",
                desc="AWS Access Key ID. Required if not using a PAM AWS Configuration.",
                required=False
            ),
            SaasConfigItem(
                id="aws_secret_access_key",
                label="AWS Secret Access Key",
                desc="AWS Secret Access Key.Required if not using a PAM AWS Configuration.",
                type="secret",
                required=False
            ),
            SaasConfigItem(
                id="aws_region",
                label="AWS Region",
                desc="AWS Region. Required if not using a PAM AWS Configuration.",
                required=False
            ),
        ]

    @classmethod
    def requirements(cls) -> List[str]:
        return ["boto3"]

    @property
    def can_rollback(self) -> bool:
        return True

    @property
    def aws_access_key_id(self) -> Optional[Secret]:
        access_key_id = self.get_config("aws_access_key_id")
        if access_key_id is None and self.provider_config is not None:
            access_key_id = Secret.get_value(self.provider_config.aws_access_key_id)

        if access_key_id is not None:
            return Secret(access_key_id)
        return None

    @property
    def aws_secret_access_key(self) -> Optional[Secret]:
        secret_access_key = self.get_config("aws_secret_access_key")
        if secret_access_key is None and self.provider_config is not None:
            secret_access_key = Secret.get_value(self.provider_config.aws_secret_access_key)

        if secret_access_key is not None:
            return Secret(secret_access_key)
        return None

    @property
    def aws_region(self) -> str:
        region = self.get_config("aws_region")
        if region is None and self.provider_config is not None:
            region_names = Secret.get_value(self.provider_config.region_names)  # type: List
            if len(region_names) > 0:
                region = region_names[0]

        if region is None:
            raise SaasException("The AWS Region is blank. Either set in the SaaS configuration "
                                "record or allow plugin access to the PAM AWS Configuration record.")

        return region

    @staticmethod
    def _using_session() -> Optional[Session]:
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is not None:
            return session
        return None

    @property
    def client(self):
        if self._client is None:
            aws_access_key_id = self.aws_access_key_id
            aws_secret_access_key = self.aws_secret_access_key
            aws_region = self.aws_region

            # If either access/secret are blank, check if we have an attached role.
            # Else which one blank.
            if aws_access_key_id is None or aws_secret_access_key is None:
                Log.debug("aws access id and secret key are blank, checking session")
                session = self._using_session()
                if session is not None:
                    Log.debug("a session exists, using it for cognito-idp authentication")
                    self._client = session.client("cognito-idp", region_name=aws_region)
                else:
                    Log.error("either the aws access id or secret key is missing")
                    if aws_access_key_id is None:
                        raise SaasException(
                            "The AWS Access Key ID is blank. Either set in the SaaS configuration record or allow "
                            "plugin access to the PAM Aws Configuration record.")
                    if aws_secret_access_key is None:
                        raise SaasException(
                            "The AWS Secret Access Key is blank. Either set in the SaaS configuration record or allow "
                            "plugin access to the PAM Aws Configuration record.")

            # Else we have access/secret from the provider or the config record.
            else:
                Log.debug("using aws access id and secret key from vault or AWS PAM configuration")
                self._client = boto3.client(
                    "cognito-idp",
                    aws_access_key_id=aws_access_key_id.value,
                    aws_secret_access_key=aws_secret_access_key.value,
                    region_name=self.aws_region
                )
        return self._client

    def admin_set_user_password(self, password: Secret):

        try:
            self.client.admin_set_user_password(
                UserPoolId=self.get_config("user_pool_id"),
                Username=self.user.username.value,
                Password=password.value,
                Permanent=True
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "UserNotFoundException":
                Log.error(f"the AWS cognito user name was not found: {err}")
                raise SaasException("The user was not found in AWS Cognito.")
            elif err.response["Error"]["Code"] == "InvalidParameterException":
                Log.error(f"illegal parameters for AWS cognito: {err}")
                raise SaasException("The username, password, or user pool id appears to be invalid.")
            elif err.response["Error"]["Code"] == "NotAuthorizedException":
                Log.error(f"user disabled or admin does not have permissions: {err}")
                raise SaasException("The user is either disabled or the administrative user does not "
                                    "proper permission.")
            elif err.response["Error"]["Code"] == "TooManyRequestsException":
                Log.error(f"user disabled or admin does not have permissions: {err}")
                raise SaasException("Exceeded the AWS limit for requests.")
            elif err.response["Error"]["Code"] == "InternalErrorException":
                Log.error(f"aws cognito internal exception: {err}")
                raise SaasException("AWS Cognito had an internal exception.")
            else:
                Log.error(f"aws cognito general exception: {err}")
                raise SaasException("Could not change AWS Cognito password.")

    def change_password(self):

        Log.info("Changing password for AWS Cognito user")
        Log.debug(f"Changing password user in user pool {self.get_config('user_pool_id')}")
        self.admin_set_user_password(
            password=self.user.new_password,
        )

        Log.info("Password changed successfully.")
    
    def rollback_password(self):

        Log.info("Rolling back password for AWS Cognito user")
        self.admin_set_user_password(
            password=self.user.prior_password,
        )
        Log.info("Password rolled back successfully.")
