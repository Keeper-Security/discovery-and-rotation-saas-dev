import click
import importlib.util
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, Field
from kdnrm.secret import Secret
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core.utils import generate_password
import traceback
import sys
from colorama import Fore, Style
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keeper_secrets_manager_core.dto.dtos import Record


def load_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@click.command(name="config")
@click.option('--file', '-f', type=str, help='Plugin python file', required=True)
def config_command(file):
    """Create a config file"""

    pass


@click.command(name="run")
@click.option('--file', '-f', type=str, help='Plugin python file', required=True)
@click.option('--user-uid', '-u', type=str, help='UID of PAM User record', required=True)
@click.option('--plugin-config-uid', '-c', type=str, help='UID of plugin config record', required=True)
@click.option('--configuration-uid', type=str, help='UID of configuration record', required=False)
@click.option('--fail', is_flag=True, help="Force run to fail")
@click.option('--password/--no-password', default=True, help="Enable or disable password rotation.")
@click.option('--pkey/--no-pkey', default=False, help="Enable or disable private key rotation.")
@click.option('--new-password',  type=str, help="New password")
def run_command(file, user_uid, plugin_config_uid, configuration_uid, fail, password, pkey, new_password):
    """Run the plugin"""

    Log()
    Log.set_log_level("DEBUG")

    try:
        storage = FileKeyValueStorage()
        sm = SecretsManager(config=storage)

        uids = [user_uid, plugin_config_uid]
        if configuration_uid is not None:
            uids.append(configuration_uid)

        records = sm.get_secrets(uids)

        user_record = next((x for x in records if x.uid == user_uid), None)  # type: Record
        config_record = next((x for x in records if x.uid == plugin_config_uid), None)  # type: Record
        provider_record = next((x for x in records if x.uid == configuration_uid), None)  # type: Record

        if user_record is None:
            raise Exception("Could not get the user record.")
        if config_record is None:
            raise Exception("Could not get the plugin config record.")

        if new_password is None and password is True:
            new_password = generate_password()

        try:
            fields = []
            for field in user_record.dict.get("custom", []):
                fields.append(
                    Field(
                        type=field.get("type"),
                        label=field.get('label'),
                        values=field.get('value')
                    )
                )

            user = SaasUser(
                username=Secret(user_record.get_standard_field_value("login", single=True)),
                new_password=Secret(new_password) if new_password is not None else None,
                prior_password=Secret(user_record.get_standard_field_value("password", single=True)),
                fields=fields
            )
        except Exception as err:
            raise Exception(f"Cannot get value from PAM USer record: {err}")

        module = load_module_from_path("test_plugin", file)
        plugin = getattr(module, "SaasPlugin")(
            user=user,
            config_record=config_record,
            force_fail=fail
        )
        try:
            plugin.run()

            if plugin.force_fail is True:
                raise Exception("FORCE FAIL FLAG SET")

            if len(plugin.return_fields) > 0:
                Log.debug("there were return custom fields")

                fields = []
                for item in plugin.return_fields:
                    value = Secret.get_value(item.value) or ""
                    fields.append({
                        "type": item.type,
                        "label": item.label,
                        "value": [value]
                    })
                Log.debug(fields)

                if user_record.dict.get("custom") is None:
                    user_record.dict["custom"] = []

                for field in fields:
                    found_field = next((x for x in user_record.dict["custom"] if x.get("label") == field.get("label")),
                                       None)
                    if found_field is not None:
                        Log.debug("found existing field, updating type and value")
                        found_field["value"] = field["value"]
                        found_field["type"] = field["type"]
                    else:
                        Log.debug("field not found, adding field")
                        user_record.dict["custom"].append(field)

                Log.debug("updating the user record.")
                user_record.set_standard_field_value("password", new_password)
                user_record._update()
                sm.save(user_record)

                print(f"{Fore.GREEN}Rotation was successful{Style.RESET_ALL}")

        except Exception as err:
            Log.error(f"got exception: {err}")

            if plugin.can_rollback is True:
                plugin.rollback()
            else:
                Log.info("the plugin cannot rollback/revert the password")

    except Exception as err:

        exc = sys.exc_info()[0]
        stack = traceback.extract_stack()[:-1]
        if exc is not None:
            del stack[-1]
        trc = 'Traceback (most recent call last):\n'
        msg = trc + ''.join(traceback.format_list(stack))
        if exc is not None:
            msg += '  ' + traceback.format_exc().lstrip(trc)
        print(msg)
        print(f"{Fore.RED}ERROR: {err}{Style.RESET_ALL}")


@click.group()
def cli():
    pass


cli.add_command(config_command)
cli.add_command(run_command)


if __name__ == '__main__':
    cli()
