from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser, SaasConfigItem
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
try:
    import boto3
except ImportError:
    raise SaasException("Missing required module: boto3 - please install it using  \"pip install boto3\"")
if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
class SaasPlugin(SaasPluginBase):
    name = "AWS Cognito"
    __user_pool_id = "<user_pool_id>"
    __cloud_region = "<cloud_region>"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="aws_access_key_id",
                label="AWS Access Key ID",
                desc="AWS Access Key ID.",
                required=True
            ),
            SaasConfigItem(
                id="aws_secret_access_key",
                label="AWS Secret Access Key",
                desc="AWS Secret Access Key.",
                type="secret",
                required=True
            ),
            SaasConfigItem(
                id="user_pool_id",
                label="User Pool ID",
                desc="User Pool ID.",
                type="secret",
                required=True
            ),
            SaasConfigItem(
                id="cloud_region",
                label="Cloud Region",
                desc="Cloud Region.",
                required=True
            ),
        ]

    @classmethod
    def requirements(cls) -> List[str]:
        return ["boto3"]

    @property
    def can_rollback(self) -> bool:
        return True

    def add_return_field(self, field: ReturnCustomField):
        """
        Add a custom field to the return value.
        """
        try:
            if not isinstance(field, ReturnCustomField):
                raise SaasException("field must be an instance of ReturnCustomField")
            existing_field = next((f for f in self.return_fields if f.label == field.label), None)
            if existing_field:
                existing_field.value = field.value
            else:
                self.return_fields.append(field)
        except Exception as e:
            raise SaasException(f"Error adding return field: {e}")
        Log.debug(f"Added return field")

    def change_password(self):
        """
        Change the password for the AWS Cognito user.
        This method connects to the AWS Cognito account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for AWS Cognito user")
        try:
            Log.debug(f"Extracting login from config record")
            access = self.get_config("aws_access_key_id")
            secret = self.get_config("aws_secret_access_key")
            user_pool_id = self.get_config("user_pool_id")
            cloud_region = self.get_config("cloud_region")
            if not all([access, secret, user_pool_id, cloud_region]):
                raise SaasException("Missing required fields in config record.")
           
            username = self.user.username.value
            new_password = self.user.new_password.value
            self.__user_pool_id = user_pool_id
            self.__cloud_region = cloud_region
            client = boto3.client(
                "cognito-idp",
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                region_name=self.__cloud_region
            )
            self._client = client
            client.admin_set_user_password(
                UserPoolId=self.__user_pool_id,
                Username=username,
                Password=new_password,
                Permanent=True
            )
            Log.debug(f"Changing password for user {username} in user pool {self.__user_pool_id}")
        except Exception as e:
            Log.error(f"Error changing password: {e.__str__()}")
            raise SaasException(f"Password change failed: {e}")
        try:
            self.add_return_field(
                ReturnCustomField(
                    label="cloud_region",
                    value=self.__cloud_region,
                    type="text",
                )
            )
        except Exception as e:
            Log.error(f"Error adding return field: {e.__str__()}")
            raise SaasException(f"Error adding return field: {e}")
        
        Log.info("Password changed successfully.")
    
    def rollback_password(self):
        try:
           self._client.admin_set_user_password(
                UserPoolId=self.__user_pool_id,
                Username=self.user.username.value,
                Password=self.user.prior_password.value[-1],
                Permanent=True
            )
           self.user.new_password = Secret(self.user.prior_password.value[-1])
        except Exception as e:
            Log.error(f"Failed rollback changing aws cognito user password: {e.__str__()}")
            raise SaasException(f"Password Change while rollback failed: {e}")
        try:
            Log.debug(f"Adding return field for rollback")
            self.add_return_field(
                ReturnCustomField(
                    label="cloud_region",
                    value=self.__cloud_region,
                    type="text",
                )
            )
        except Exception as e:
            raise SaasException(f"Error saving add_return_field for rollback: {e}") 
        Log.info("Password rolled back successfully.")