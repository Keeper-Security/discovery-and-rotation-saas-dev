from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import SaasConfigItem, ReturnCustomField
from kdnrm.log import Log
from kdnrm.secret import Secret
from typing import List


class SaasPlugin(SaasPluginBase):

    # Name of the plugin.
    # This should not be changed after the release; it will affect the customer's mapping.
    name = "Hello World"
    summary = "Simple Hello Plugin"
    readme = None
    author = "John Doe"
    email = "jdoe@hotmail.com"

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="my_msg",
                label="My Message",
                desc="This is the message that will be displayed. The field is required.",
                required=True
            ),
            SaasConfigItem(
                id="my_optional",
                label="My Optional",
                desc="This is an optional field, but is secret if it exists",
                type="secret",
                default_value="This is a secret",
                required=False
            )
        ]

    @property
    def can_rollback(self):
        return True

    def change_password(self):

        Log.info("starting rotating of the Hello World user")

        message = self.get_config("my_msg")

        self.add_return_field(
            ReturnCustomField(
                label="Hello World Label",
                value=Secret(message)
            )
        )

        Log.info("rotating the user in Hello World was a success")

    def rollback_password(self):

        Log.info("starting rollback of the Hello World user")

        # Add code to roll back what change_password() did.

        Log.info("rolling back the user in Hello World was a success")
