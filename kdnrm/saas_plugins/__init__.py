from __future__ import annotations
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.utils import value_to_boolean
from kdnrm.saas_type import Field
import re
from typing import Optional, List, Any, Dict, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from keeper_secrets_manager_core.dto.dtos import Record
    from kdnrm.saas_type import ReturnCustomField, SaasUser, SaasConfigItem


class SaasPluginBase:

    name: str = "NA"
    summary: str = ""
    readme: Optional[str] = None
    author: Optional[str] = None
    email: Optional[str] = None
    allow_non_admin: bool = False

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

                elif item.type == "record":
                    if len(value) != 22:
                        raise SaasException(f"For {self.name}, the field {item.label} did not have a "
                                            "valid record UID.",
                                            code="gateway_kdnrm_saas_dt_uid",
                                            values={
                                                "XXXSAASXXX": self.name,
                                                "XXXFIELDXXX": item.label
                                            })

                    record_fields = self.get_record_fields(value)
                    if record_fields is not None:
                        self.record_lookup[value] = record_fields

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
                 force_fail: bool = False,
                 **kwargs):

        self.user = user
        self.config_record = config_record
        self.force_fail = force_fail
        self.name = self.__class__.name
        self._record_lookup_func = kwargs.get("record_lookup_func")

        # Get the fields from the record and make a dictionary.
        # The key to the dictionary is the id of the config_schema
        # If there are any `record` types, they will be populated in a dictionary by their record UID.
        self.record_lookup = {}  # type: Dict[str, List]
        self.field_config = self._get_config_mapping(config_record)
        self.provider_config = provider_config

        self.return_fields = []  # type: List[ReturnCustomField]

        # Common name for the remote management instance.
        # Can be used for a persistent client
        self._client = None

    def get_record_fields(self, record_uid: str) -> List[Field]:
        """
        Return a list of fields for record.
        """
        if self._record_lookup_func is None:
            raise Exception("The plugin does use record lookup.")
        return self._record_lookup_func(record_uid)

    def get_record_value(self,
                         record_uid: str,
                         field_type: Optional[str] = None,
                         label: Optional[str] = None,
                         single_value: bool = True) -> List[Any]:

        """
        Get the list of values for the field using the field type and/or label.

        The field_type and label are case-sensitive.

        """
        if self._record_lookup_func is None:
            raise Exception("The plugin does use record lookup.")

        if record_uid not in self.record_lookup:
            raise SaasException(f"Could not record UID {record_uid}.")

        value_list = []
        for field in self.record_lookup[record_uid]:  # type: Field
            if (field_type is not None
                    and label is not None
                    and field.type == field_type
                    and field.label == label):
                value_list.append(field.values)
            elif field_type is not None and field.type == field_type:
                value_list.append(field.values)
            elif label is not None and field.label == label:
                value_list.append(field.values)

        if not single_value:
            return value_list

        single_value_list = []
        for value in value_list:
            if value is None or len(value) == 0:
                single_value_list.append(None)
            else:
                single_value_list.append(value[0])
        return single_value_list

    def get_config(self, key: str, default: Optional[Any] = None) -> Any:
        return self.field_config.get(key, default)

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
