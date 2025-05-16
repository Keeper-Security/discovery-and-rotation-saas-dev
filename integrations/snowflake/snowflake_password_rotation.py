from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, Secret, SaasUser
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
try:
    import snowflake.connector
except ImportError:
    raise SaasException("Missing required module: snowflake-connector-python")

if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

class SaasPlugin(SaasPluginBase):
    name = "Snowflake Plugin"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record

    @classmethod
    def requirements(cls) -> List[str]:
        return ["snowflake-connector-python"]
  
    @property
    def can_rollback(self) -> bool:
        return True

    def add_return_field(self, field: ReturnCustomField):
        """
        Add a custom field to the return value.
        """
        Log.debug(f"Adding return field")
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
        Change the password for the Snowflake user.
        This method connects to the Snowflake account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Snowflake user")
        try:
            new_password = self.user.new_password.value
    
            admin_authentication_record = self.config_record.dict.get('fields', [])
            if not isinstance(admin_authentication_record, list):
                raise SaasException("Expected 'fields' to be a list in config_record.")

            Log.debug(f"Extracting login from config record")
            snowflake_admin_user = next((field['value'][0] for field in admin_authentication_record if field['type'] == 'login'), None)
            if not snowflake_admin_user:
                raise SaasException("Missing 'login' field in config record.")
            
            Log.debug(f"Extracting password from config record")
            snowflake_admin_pass = next((field['value'][0] for field in admin_authentication_record if field['type'] == 'password'), None)
            if not snowflake_admin_pass:
                raise SaasException("Missing 'password' field in config record.")
            
            Log.debug(f"Extracting snowflake_account_name from config record")
            custom_fields = self.config_record.dict.get('custom', [])
            if not isinstance(custom_fields, list):
                raise SaasException("Expected 'custom' to be a list in config_record.")
            snowflake_account_name = next((custom['value'][0] for custom in custom_fields if custom['label'] == 'snowflake_account_name'), None)

            snowflake_rotated_user_name = self.user.username.value

            # Extract new rotated password..
            new_password = self.user.new_password.value
            
            if not all([snowflake_account_name, snowflake_admin_user, snowflake_admin_pass]):
                raise SaasException(f"Error: One or more required fields are missing in the authentication record.")
            
            try:
                conn = snowflake.connector.connect(
                user=snowflake_admin_user,
                password=snowflake_admin_pass,
                account=snowflake_account_name
                )
            except Exception as E:
                raise SaasException(f"Unable to connect to snowflake account. Error: {E}")
            
            cur = conn.cursor()
            try:
                change_pass_query = f'ALTER USER "{snowflake_rotated_user_name}" SET PASSWORD = %s'
                cur.execute(change_pass_query, (new_password,))
            except Exception as E:
                raise SaasException(f"Unable to update the password. Error: {E}")

            Log.debug(f"Closing cursor")
            cur.close()
            
            Log.debug(f"Closing connection")
            conn.close()
            
            Log.info("Password changed successfully.")
        except Exception as e:
            raise SaasException(f"Password change failed: {e}")
        
        try:
            Log.debug(f"Adding return field")
            self.add_return_field(
            ReturnCustomField(
                label="snowflake_account_name",
                type="secret",
                value=Secret(snowflake_account_name)
            ))
        except Exception as e:
            raise SaasException(f"Error saving add_return_field: {e}")
        
    def rollback_password(self):
        try:
            Log.debug("Rolling back password for Snowflake user")
            if not self.user.prior_password:
                raise SaasException("No prior password to roll back to.")
            self.user.new_password = Secret(self.user.prior_password.value)
            Log.info("Password rolled back successfully.")
        except Exception as e:
            raise SaasException(f"Rollback failed: {e}")