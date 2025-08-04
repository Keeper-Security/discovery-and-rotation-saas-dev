from __future__ import annotations
import click
import importlib.util
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, Field, AwsConfig, AzureConfig, DomainConfig, NetworkConfig
from kdnrm.secret import Secret
from kdnrm.utils import value_to_boolean
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core.core import RecordCreate
from keeper_secrets_manager_core.utils import generate_password
import traceback
import sys
import os
from colorama import Fore, Style
from typing import Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from keeper_secrets_manager_core.dto.dtos import Record
    from kdnrm.saas_type import SaasConfigItem


def load_module_from_path(module_name, file_path):
    """
    Load a module from a file path.
    """
    if os.path.exists(file_path) is False:
        raise Exception(f"The plugin {file_path} does not exist.")

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _get_field_value(item: SaasConfigItem) -> dict:

    req = f"{Fore.RED}Required:{Style.RESET_ALL}"
    if not item.required:
        req = f"{Fore.BLUE}Optional:{Style.RESET_ALL}"

    print(f"{req} {item.label}")
    print(f"{item.desc}")
    if item.type == "multiline":
        print("Enter path to read from local file.")
    default = ""
    if item.default_value is not None:
        default = f" (default: {item.default_value})"
    value = input(f"Enter Value {default}: > ")

    if os.path.exists(value):
        with open(value, "r") as fh:
            value = fh.read()

    field_type = item.type
    if field_type in ["url", "int", "number", "bool", "enum"]:
        field_type = "text"

    field_args = {
        "type": field_type,
        "label": item.label,
        "value": []
    }
    if value is not None:
        field_args["value"] = [value]
    if item.is_secret:
        field_args["privacyScreen"] = True

    print("")

    return field_args


@click.command(name="config")
@click.option('--file', '-f', type=str, help='Plugin python file', required=True)
@click.option('--shared-folder-uid', '-s', type=str, help='Shared folder UID', required=True)
@click.option('--title', '-t', type=str, help='SaaS config record tile', required=True)
@click.option('--config', type=str, help='KSM configuration file', required=False)
def config_command(file, shared_folder_uid, title, config):
    """Create a config file"""

    Log()
    Log.set_log_level("INFO")

    module = load_module_from_path("test_plugin", file)
    plugin = getattr(module, "SaasPlugin")
    schema = getattr(plugin, "config_schema")()

    fields = [
        {
            "label": "SaaS Type",
            "type": "text",
            "value": [plugin.name]
        }
    ]

    for item in schema:  # type: SaasConfigItem
        if item.required:
            fields.append(_get_field_value(item))

    for item in schema:  # type: SaasConfigItem
        if not item.required:
            fields.append(_get_field_value(item))

    if config is None:
        config = "config.json"
    FileKeyValueStorage.default_config_file_location = config

    storage = FileKeyValueStorage()
    sm = SecretsManager(config=storage)

    new_record = RecordCreate("login", title=title)
    new_record.fields = []
    new_record.custom = fields
    record_uid = sm.create_secret(shared_folder_uid, new_record)

    print(f"{Fore.GREEN}Configuration record UID is {record_uid}{Style.RESET_ALL}")


@click.command(name="run")
@click.option('--file', '-f', type=str, help='Plugin python file', required=True)
@click.option('--user-uid', '-u', type=str, help='UID of PAM User record', required=True)
@click.option('--plugin-config-uid', '-c', type=str, help='UID of plugin config record', required=True)
@click.option('--configuration-uid', type=str, help='UID of configuration record', required=False)
@click.option('--fail', is_flag=True, help="Force run to fail")
@click.option('--new-password',  type=str, help="New password")
@click.option('--old-password',  type=str, help="Old password")
@click.option('--no-old-password', is_flag=True, help="Do not use old password")
@click.option('--config', type=str, help='KSM configuration file', required=False)
def run_command(file, user_uid, plugin_config_uid, configuration_uid, fail, new_password, old_password,
                no_old_password, config):
    """Run the plugin"""

    Log()
    Log.set_log_level("DEBUG")

    def _gfv(record: Record, label: str, is_secret=False) -> Optional[Any]:

        for access in ["get_standard_field_value", "get_custom_field_value"]:
            try:
                field_value = getattr(record, access)(label, single=True)
                if field_value is None:
                    return None
                if is_secret is False:
                    return field_value
                else:
                    return Secret(field_value)
            except (Exception,):
                pass
        return None

    try:
        if config is None:
            config = "config.json"
        FileKeyValueStorage.default_config_file_location = config

        storage = FileKeyValueStorage()
        sm = SecretsManager(config=storage)

        uids = [user_uid, plugin_config_uid]
        if configuration_uid is not None:
            uids.append(configuration_uid)

        records = sm.get_secrets(uids)

        user_record = next((x for x in records if x.uid == user_uid), None)  # type: Record
        config_record = next((x for x in records if x.uid == plugin_config_uid), None)  # type: Record

        provider_config = None
        provider_record = next((x for x in records if x.uid == configuration_uid), None)  # type: Record
        if provider_record is not None:
            if provider_record.type == "pamAwsConfiguration":
                provider_config = AwsConfig(
                    aws_access_key_id=_gfv(provider_record, "pamawsaccesskeyid", True),
                    aws_secret_access_key=_gfv(provider_record, "pamawsaccesssecretkey", True),
                    region_names=_gfv(provider_record, "pamawsregionname"),
                )
            elif provider_record.type == "pamAzureConfiguration":
                resource_groups_str = _gfv(provider_record, "pamazureresourcegroup")
                resource_groups = [x.strip() for x in resource_groups_str.split("\n")]

                provider_config = AzureConfig(
                    subscription_id=_gfv(provider_record, "pamazuresubscriptionid", True),
                    tenant_id=_gfv(provider_record, "pamazuretenantid", True),
                    application_id=_gfv(provider_record, "pamazureclientid", True),
                    client_secret=_gfv(provider_record, "pamazureclientsecret", True),
                    resource_groups=resource_groups,
                    authority=_gfv(provider_record, "Azure Authority FQDN"),
                    graph_endpoint=_gfv(provider_record, "Azure Graph Endpoint"),
                )

            # Cannot do the domain controller fully.
            # We need to graph to get the admin user.
            elif provider_record.type == "pamDomainConfiguration":
                Log.warning("currently cannot get the admin credentials for the domain controller.")
                host_and_port = _gfv(provider_record, "pamazuresubscriptionid", True),
                if host_and_port is None:
                    host_and_port = {}
                hostname = host_and_port.get("hostName")
                port = None
                try:
                    port = int(host_and_port.get("port"))
                except (Exception,):
                    pass

                provider_config = DomainConfig(
                    hostname=hostname,
                    port=port,
                    username=Secret("Cannot get value"),
                    dn=Secret("Cannot get value"),
                    password=Secret("Cannot get value"),
                    use_ssl=value_to_boolean(_gfv(provider_record, "useSSL")),
                )
            elif provider_record.type == "pamNetworkConfiguration":
                cidrs_str = _gfv(provider_record, "pamnetworkcidr")
                cidrs = [x.strip() for x in cidrs_str.split("\n")]
                provider_config = NetworkConfig(
                    cidrs=cidrs
                )

        if user_record is None:
            raise Exception("Could not get the user record.")
        if config_record is None:
            raise Exception("Could not get the plugin config record.")

        if new_password is None:
            new_password = generate_password()

        # Determine operation type early to handle password field correctly
        module = load_module_from_path("test_plugin", file)
        plugin_class = getattr(module, "SaasPlugin")
        
        # Check if methods are actually implemented in the plugin class (not just inherited)
        def _has_real_implementation(class_obj, method_name):
            """Check if method is actually implemented (not inherited empty method)."""
            if method_name not in class_obj.__dict__:
                return False
            method = getattr(class_obj, method_name)
            if not callable(method):
                return False
            # Additional check: ensure it's not just a lambda that returns None
            if hasattr(method, '__name__') and method.__name__ == '<lambda>':
                # Could add more sophisticated lambda checking here
                pass
            return True

        has_rotate_api_key = _has_real_implementation(plugin_class, 'rotate_api_key')
        has_change_password = _has_real_implementation(plugin_class, 'change_password')

        if has_rotate_api_key:
            operation_type = "api_key"
        elif has_change_password:
            operation_type = "password"
        else:
            raise Exception("Plugin must implement either 'rotate_api_key()' or 'change_password()' method")
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

            # Handle different operation types with different field requirements
            if operation_type == "password":
                # For password rotation: fetch standard fields (login, password)
                if old_password is None:
                    old_password = user_record.get_standard_field_value("password", single=True)
                if no_old_password is True:
                    old_password = None

                user = SaasUser(
                    username=Secret(user_record.get_standard_field_value("login", single=True)),
                    new_password=Secret(new_password) if new_password is not None else None,
                    prior_password=Secret(old_password) if old_password is not None else None,
                    fields=fields
                )
            else:
                # For API key rotation: only use custom fields, no standard fields
                user = SaasUser(
                    username=Secret(None),
                    new_password=Secret(None),
                    prior_password=Secret(None),
                    fields=fields
                )
        except Exception as err:
            raise Exception(f"Cannot get value from PAM User record: {err}")

        plugin = plugin_class(
            user=user,
            config_record=config_record,
            provider_config=provider_config,
            force_fail=fail
        )
        
        try:
            # Execute the appropriate operation based on detected functionality
            if operation_type == "api_key":
                Log.debug("Plugin supports rotate_api_key functionality")
                plugin.rotate_api_key()
            elif operation_type == "password":
                Log.debug("Plugin supports change_password functionality")
                plugin.change_password()

            if plugin.force_fail is True:
                raise Exception("FORCE FAIL FLAG SET")

            if len(plugin.return_fields) > 0:
                Log.debug("there were return custom fields")

                fields = []
                for item in plugin.return_fields:
                    value = Secret.get_value(item.value) or ""
                    Log.debug(f"setting the return custom field '{item.label}'")
                    fields.append({
                        "type": item.type,
                        "label": item.label,
                        "value": [value]
                    })

                if user_record.dict.get("custom") is None:
                    user_record.dict["custom"] = []

                for field in fields:
                    found_field = next((x for x in user_record.dict["custom"] if x.get("label") == field.get("label")),
                                       None)
                    if found_field is not None:
                        Log.debug(f"found existing '{field['label']}' custom field in user record, "
                                  "updating type and value")
                        found_field["value"] = field["value"]
                        found_field["type"] = field["type"]
                    else:
                        Log.debug(f"custom field '{field['label']}' does not exist in user record, adding custom field")
                        user_record.dict["custom"].append(field)

            Log.debug("updating the user record.")
            
            # Handle different types of operations
            if operation_type == "password":
                user_record.set_standard_field_value("password", new_password)
            elif operation_type == "api_key":
                # For API key rotation, use set_custom_field_values for any additional fields
                if hasattr(plugin, 'set_custom_field_values') and callable(getattr(plugin, 'set_custom_field_values')):
                    Log.debug("Setting custom field values for API key rotation")
                    plugin.set_custom_field_values(user_record)
        
            getattr(user_record, "_update")()
            sm.save(user_record)

            print(f"{Fore.GREEN} {operation_type.upper()} Rotation was successful{Style.RESET_ALL}")

        except Exception as err:
            Log.traceback(err)
            Log.error(f"got exception: {err}")

            if plugin.can_rollback is True:
                try:
                    # Check which rollback method to use based on operation type
                    if operation_type == "api_key" and hasattr(plugin, 'rollback_api_key') and callable(getattr(plugin, 'rollback_api_key')):
                        Log.debug("Rolling back API key rotation")
                        plugin.rollback_api_key()
                    elif operation_type == "password" and hasattr(plugin, 'rollback_password') and callable(getattr(plugin, 'rollback_password')):
                        Log.debug("Rolling back password rotation")
                        plugin.rollback_password()
                    else:
                        Log.debug("No rollback method found, implementing rollback_password or rollback_api_key method")
                    print(f"{Fore.YELLOW}Rotation failed, Rollback was successful{Style.RESET_ALL}")
                except Exception as rollback_err:
                    Log.traceback(rollback_err)
                    print(f"{Fore.RED}Rotation and rollback were NOT successful{Style.RESET_ALL}")
            else:
                operation_name = "API key" if operation_type == "api_key" else "password"
                Log.info(f"the plugin cannot rollback/revert the {operation_name}")
                print(f"{Fore.RED}Rotation was NOT successful{Style.RESET_ALL}")

    except Exception as err:

        exc = sys.exc_info()[0]
        stack = traceback.extract_stack()[:-1]
        if exc is not None:
            del stack[-1]
        trc = 'Traceback (most recent call last):\n'
        msg = trc + ''.join(traceback.format_list(stack))
        if exc is not None:
            formatted_exc = traceback.format_exc()
            if formatted_exc.startswith(trc):
                formatted_exc = formatted_exc[len(trc):]
            msg += '  ' + formatted_exc
        print(msg)
        print(f"{Fore.RED}TEST ENV ERROR: {err}{Style.RESET_ALL}")


@click.group()
def cli():
    pass


cli.add_command(config_command)
cli.add_command(run_command)


def main():
    cli()


if __name__ == '__main__':
    main()
