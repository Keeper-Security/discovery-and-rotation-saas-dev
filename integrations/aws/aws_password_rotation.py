from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser, SaasConfigItem
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
try:
    import boto3
except ImportError:
    raise SaasException(f"Missing required module: boto3. Please install it using \"pip install boto3\"")
if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
class SaasPlugin(SaasPluginBase):
    name = "AWS Post Rotation Plugin"
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
        Change the password for the AWS Plugin user.
        This method connects to the AWS Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for AWS Plugin user")
        try:
            access = self.get_config("aws_access_key_id")
            secret = self.get_config("aws_secret_access_key")
            cloud_region = self.get_config("cloud_region")
            if not all([access, secret, cloud_region]):
                raise SaasException("Missing required configuration values.")
            client = boto3.client('iam',
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                region_name=cloud_region)
            self._client = client
            
            aws_user_login = self.user.username.value
            new_password = self.user.new_password.value
            sts = boto3.client('sts')
            response = sts.get_caller_identity()
            account_id = response["Account"]
            client.update_login_profile(
                UserName=aws_user_login,
                Password=new_password,
                PasswordResetRequired=False
            )

        except Exception as e:
            raise SaasException(f"Password change failed: {e}")
        Log.info("Password changed successfully.")
        try:
            Log.debug(f"Adding return field")
            self.add_return_field(
                ReturnCustomField(
                    label="account_id_or_alias",
                    value=Secret(account_id),
                    desc="AWS Account ID",
                    type="secret",
                ),
            )
        except Exception as e:
            raise SaasException(f"Error saving add_return_field: {e}")
    
    def rollback_password(self):
        try:
            Log.debug("Rolling back password for AWS Plugin  user")
            self.user.new_password = Secret(self.user.prior_password.value[-1])
            Log.info("Password rolled back successfully.")
        except Exception as e:
            raise SaasException(f"Rollback failed: {e}")