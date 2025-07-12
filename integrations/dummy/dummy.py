from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import SaasConfigItem, ReturnCustomField, ReturnAttachFile, SaasConfigEnum
from kdnrm.log import Log
from kdnrm.secret import Secret
from datetime import datetime
from contextlib import redirect_stdout
import io
from art import tprint
from typing import List


class SaasPlugin(SaasPluginBase):

    name = "Dummy"
    summary = "Simple plugin that prints a message to the log and added a field to PAM User record."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="dummy_text",
                label="Dummy Text",
                desc="Just enter some required text.",
                required=True
            ),
            SaasConfigItem(
                id="dummy_art",
                label="Font Type",
                desc="Set the font type.",
                required=False,
                enum_values=[
                    SaasConfigEnum(value="block"),
                    SaasConfigEnum(value="bulbhead"),
                    SaasConfigEnum(value="slant"),
                ],
                default_value="block"
            ),
        ]

    @classmethod
    def requirements(cls) -> List[str]:
        return ["art"]

    @property
    def can_rollback(self):
        return False

    def change_password(self):

        Log.info("starting rotating of the Dummy user")

        Log.info("***************************************************")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            tprint(self.get_config("dummy_text"))
        Log.info("\n" + buffer.getvalue() + "\n")
        Log.info("***************************************************")

        now = datetime.now()
        self.add_return_field(
            ReturnCustomField(
                label="This Was Run On",
                value=Secret(now.strftime("%Y-%m-%d %H:%M:%S"))
            )
        )

        self.add_file(
            ReturnAttachFile(
                title="Dummy File",
                content=f"THIS IS A DUMMY FILE: {now}".encode()
            )
        )

        Log.info("rotating the user in Hello World was a success")
