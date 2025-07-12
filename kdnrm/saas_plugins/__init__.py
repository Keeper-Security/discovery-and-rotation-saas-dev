from __future__ import annotations
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.utils import value_to_boolean
import re
from typing import Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from keeper_secrets_manager_core.dto.dtos import Record, KeeperFile
    from kdnrm.saas_type import ReturnCustomField, ReturnAttachFile, SaasUser, SaasConfigItem


class SaasPluginBase:

    name = "NA"
    summary = ""
    readme = None
    author = None
    email = None

    @classmethod
    def requirements(cls) -> List[str]:
        return []

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return []

    def _get_config_mapping(self, config_record: Record) -> dict:

        """
        From the record custom fields, load the configuration by the field labels.
        """

        config = {}
        for item in self.__class__.config_schema():
            value = None

            # For now, we use the label
            try:
                value = config_record.get_custom_field_value(item.label, single=True)
                if value is not None:
                    value = value.strip()
                if value == "":
                    value = None
            except (Exception,):
                pass

            # If the value is None, set it to the default value.
            if value is None:
                value = item.default_value
                if value is None:
                    Log.info(f"could not retrieve the custom field '{item.label}'")

            if value is not None:
                # If a password, add the value to the secret.
                if item.type == "secret":
                    Log.add_secret(value)

                if item.type == "url":
                    found = re.match(r"^http.*://", value, re.IGNORECASE)
                    if found is None:
                        Log.error(f"For {self.name}, the field {item.label}, {value} is not a URL")
                        raise SaasException(f"For {self.name}, the field {item.label} does not appears "
                                            "to be a URL.",
                                            code="gateway_kdnrm_saas_dt_url",
                                            values={
                                                "XXXSAASXXX": self.name,
                                                "XXXFIELDXXX": item.label
                                            })

                elif item.type == "int":
                    try:
                        value = int(value)
                    except Exception as err:
                        Log.error(f"For {self.name}, the field {item.label}, {value} is not an integer "
                                  f"number: {err}")
                        raise SaasException(f"For {self.name}, the field {item.label} is not "
                                            "an integer number.",
                                            code="gateway_kdnrm_saas_dt_int",
                                            values={
                                                "XXXSAASXXX": self.name,
                                                "XXXFIELDXXX": item.label
                                            })

                elif item.type == "number":
                    try:
                        value = float(value)
                    except Exception as err:
                        Log.error(f"For {self.name}, the field {item.label}, {value} is not an number: {err}")
                        raise SaasException(f"For {self.name}, the field {item.label} is not "
                                            "a number.",
                                            code="gateway_kdnrm_saas_dt_num",
                                            values={
                                                "XXXSAASXXX": self.name,
                                                "XXXFIELDXXX": item.label
                                            })

                elif item.type == "bool":
                    value = value_to_boolean(value)

                elif item.type == "enum":
                    valid_values = [x.value for x in item.enum_values]
                    if value not in valid_values:
                        Log.error(f"For {self.name}, the field {item.label}, value {value} is not value. Valid "
                                  f"values are {', '.join(valid_values)}")
                        raise SaasException(f"For {self.name}, the field {item.label} did not have a "
                                            "valid value.",
                                            code="gateway_kdnrm_saas_dt_enum",
                                            values={
                                                "XXXSAASXXX": self.name,
                                                "XXXFIELDXXX": item.label
                                            })

            if item.required is True and value is None:
                Log.error(f"For {self.name}, the field {item.label} is required, but not set.")
                raise SaasException(f"For {self.name}, the field {item.label} is required",
                                    code="gateway_kdnrm_saas_value_req",
                                    values={
                                        "XXXSAASXXX": self.name,
                                        "XXXFIELDXXX": item.label
                                    })

            config[item.id] = value
        return config

    def __init__(self,
                 user: SaasUser,
                 config_record: Record,
                 provider_config: Optional[Any] = None,
                 force_fail: bool = False):

        self.user = user
        self.config_record = config_record
        self.force_fail = force_fail
        self.name = self.__class__.name

        # Get the fields from the record and make a dictionary.
        # The key to the dictionary is the id of the config_schema
        self.field_config = self._get_config_mapping(config_record)
        self.provider_config = provider_config

        self.return_fields = []  # type: List[ReturnCustomField]
        self.attach_files = []  # type: List[ReturnAttachFile]

        # Common name for the remote management instance.
        # Can be used for a persistent client
        self._client = None

    def get_config(self, key: str, default: Optional[Any] = None) -> Any:
        value = self.field_config.get(key)
        if value is None or str(value).strip() == "":
            value = default
        return value

    def file_exists(self, title: str) -> bool:
        """
        Check if the file exists on the PAM User record.
        """
        return title in self.user.files

    def download_file(self, title: str) -> bytes:
        """
        Download the file and return the bytes.

        If the content is a string, use decode() to covert bytes to string.
        """

        if not self.file_exists(title):
            raise SaasException(f'The file "{title}" does not exists.')

        file = self.user.files[title]  # type: KeeperFile
        return file.get_file_data()

    @property
    def can_rollback(self) -> bool:
        """
        Does the SaaS service allow rolling back the password?

        A lot of services will not allow you to re-user a password after changing it.
        """
        return False

    def add_return_field(self, field: ReturnCustomField):
        """
        Add or update a custom field in the pamUser record.

        The fields will be the secret type.
        """

        self.return_fields.append(field)

    def add_file(self, file: ReturnAttachFile):
        """
        Attach a file to the pamUser record.

        It will replace an existing file.
        """

        self.attach_files.append(file)

    def change_password(self):
        """
        Perform the password rotation.
        """

        pass

    def rollback_password(self):
        """
        Attempt to revert the password after a failure.
        """

        pass
