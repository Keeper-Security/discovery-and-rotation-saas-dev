from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from botocore.exceptions import ClientError
from typing import List, TYPE_CHECKING
from kdnrm.log import Log

try:  # pragma: no cover
    import boto3
except ImportError:  # pragma: no cover
    raise SaasException("Missing required module: boto3 - please install it using  \"pip install boto3\"")
if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):
    name = "AWS Cognito"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self._client = None
        self.user_pool_id = "<user_pool_id>"
        self.cloud_region = "<cloud_region>"
    
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
                desc="AWS Access Key ID.",
                required=False
            ),
            SaasConfigItem(
                id="aws_secret_access_key",
                label="AWS Secret Access Key",
                desc="AWS Secret Access Key.",
                type="secret",
                required=False
            ),
            SaasConfigItem(
                id="aws_region",
                label="AWS Region",
                desc="AWS Region.",
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
    def aws_access_key_id(self) -> Secret:
        access_key_id = self.get_config("aws_access_key_id")
        if access_key_id is None and self.provider_config is not None:
            access_key_id = Secret.get_value(self.provider_config.aws_access_key_id)

        if access_key_id is None:
            raise SaasException("The AWS Access Key ID is blank. Either set in the SaaS configuration record or allow "
                                "plugin access to the PAM Aws Configuration record.")

        return Secret(access_key_id)

    @property
    def aws_secret_access_key(self) -> Secret:
        secret_access_key = self.get_config("aws_secret_access_key")
        if secret_access_key is None and self.provider_config is not None:
            secret_access_key = Secret.get_value(self.provider_config.aws_secret_access_key)

        if secret_access_key is None:
            raise SaasException("The AWS Secret Access Key ID is blank. Either set in the SaaS configuration "
                                "record or allow plugin access to the PAM AWS Configuration record.")

        return Secret(secret_access_key)

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

    @property
    def client(self):
        if self._client is None:
            self._client = boto3.client(
                "cognito-idp",
                aws_access_key_id=self.aws_access_key_id.value,
                aws_secret_access_key=self.aws_secret_access_key.value,
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
        self.admin_set_user_password(
            password=self.user.new_password,
        )
        Log.debug(f"Changing password user in user pool {self.user_pool_id}")

        self.add_return_field(
            ReturnCustomField(
                label="cloud_region",
                value=self.cloud_region,
                type="text",
            )
        )

        Log.info("Password changed successfully.")
    
    def rollback_password(self):

        Log.info("Rolling back password for AWS Cognito user")

        self.admin_set_user_password(
            password=self.user.prior_password,
        )
        Log.info("Password rolled back successfully.")
