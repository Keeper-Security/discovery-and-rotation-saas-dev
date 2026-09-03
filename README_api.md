# SaaS Plugin API Reference

This document provides a complete reference for developing SaaS rotation plugins for KeeperPAM.

## Table of Contents

- [Secret Class](#secret-class)
  - [\_\_init\_\_(value)](#__init__value)
  - [value property](#value---any-property-setter)
  - [value_strip property](#value_strip---any-property)
  - [bytes property](#bytes---bytes-property)
  - [get_value() staticmethod](#get_valuesecret---any-staticmethod)
  - [get_secret() staticmethod](#get_secretvalue---secret-staticmethod)
- [SaasException](#saasexception)
- [SaasPluginBase Class](#saaspluginbase-class)
  - [Class Attributes](#class-attributes)
  - [Instance Attributes](#instance-attributes)
    - [user : SaasUser](#user--saasuser)
    - [config_record : Record](#config_record--record)
    - [provider_config : BaseModel](#provider_config--basemodel-optional)
    - [force_fail : bool](#force_fail--bool--false)
  - [Methods](#methods)
    - [requirements()](#requirements)
    - [config_schema()](#config_schema)
    - [\_\_init\_\_()](#__init__)
    - [can_rollback property](#can_rollback---bool-property)
    - [get_config()](#get_configfield_id-default_value---any)
    - [add_return_field()](#add_return_fieldreturncustomfield)
    - [get_record_value()](#get_record_valuerecord_uid-field_type-label-single_value---listany)
    - [get_record_fields()](#get_record_fieldsrecord_uid---listfield)
    - [change_password()](#change_password)
    - [rollback_password()](#rollback_password)
- [Configuration Classes](#configuration-classes)
  - [SaasConfigItem](#saasconfigitem-class)
  - [SaasConfigEnum](#saasconfigenum-class)
- [Provider Configuration Types](#provider-configuration-types)
  - [AWS](#aws)
  - [Azure](#azure)
  - [Domain Controller](#domain-controller)
  - [Network](#network)
  - [Google Cloud Provider](#google-cloud-provider)
  - [OKTA](#okta)

---

# Secret Class

The Secret class is used to prevent memory leaks.
Values placed in this instance are encrypted.
If there is crash, and a core file is created, this class prevent from plain text from being in the core file.

## __init__(value)

```python
my_secret = Secret("My super secret value.")
```

## value -> Any; property; setter

Get or set the decrypted value.


```python
# Set via initializer 
my_secret = Secret("My super secret value.")

# Get the value
viewable_value = my_secret.value

# Set the secret to a new secret value
my_secret.value = "New Secret"
```

## value_strip -> Any; property

This is the same as the value property, except it will strip spaces and whitespace from the returned value.

```python
my_secret = Secret("   My super secret value.   ")
viewable_value = my_secret.value
# viewable_value = "My super secret value."
```

## bytes -> bytes; property

This property will return the encrypted values as bytes

```python
my_secret = Secret("My super secret value.")
bytes_value = my_secret.bytes
# b'My super secret value.'

```

## get_value(secret) -> Any; staticmethod

Get the value from Secret, if the instance passed in is a Secret else return the value passed in.
This is used if you do not know the instance a secret or not.

```python
# This will decrypt and return the actual value.
my_secret = Secret("My super secret value.")
viewable_value = Secret.get_value(my_secret)

# This will just return the string that is passed in.
viewable_value = Secret.get_value("My super secret value.")
```

## get_secret(value) -> Secret; staticmethod

Return a secret if the value is not a Secret, else return the Secret that was passed in.
This is used if you do not know the instance a secret or not, and you want a Secret.

```python
# This will return the same Secret instance.
my_secret = Secret("My super secret value.")
my_secret = Secret.get_secret(my_secret)

# This will encrypt the value and return a Secret.
new_secret = Secret.get_secret("My super secret value.")
```

---

# SaasException

If the SaaS rotation fail, it is required to throw this exception with an appropriate error message.
The `change_password` and `rollback_password` do not return a success or fail value.
If these method do not return an exception, the rotation will be considered successful.

```python
from kdnrm.exceptions import SaasException
```

---

# SaasPluginBase class

```python
from __future__ import annotations
from kdnrm.saas_plugins import SaasConfigItem
from kdnrm.saas_type import ReturnCustomField
from typing import Optional, List, Any, TYPE_CHECKING

# Only needed if you need a special module.
# Should match requirements.
try:  # pragma: no cover
    import some_sdk_module
except ImportError:  # pragma: no cover
    pass

if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
    

class SaasPluginBase:
    
    # Name of the Plugin. Do not change after setting committing.
    name = "NA"
    
    # Short summary of the plugin.
    summary = ""
    
    # Path to documentation in the repo.
    readme = None
    
    # Name of the person who wrote the plugin.
    author = None
    
    # Email for contact.
    email = None
    
    @classmethod
    def requirements(cls) -> List[str]:
        return ["some_sdk_module"]
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return []
    
    @property
    def can_rollback(self) -> bool:
        """
        Does the SaaS service allow rolling back the password?
        A lot of services will not allow you to re-user a password after changing it.
        """
        return False
    
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
```

## Instance Attributes

### user : SaaSUser

The `user` is an instance of `SaaSUser`.

```python
class Field(BaseModel):
    type: str
    label: str
    values: List[Any]

class SaasUser(BaseModel):
    username: Secret
    dn: Optional[Secret] = None
    new_password: Optional[Secret] = None
    prior_password: Optional[Secret] = None
    new_private_key: Optional[Secret] = None
    prior_private_key: Optional[Secret] = None
    database: Optional[str] = None
    fields: List[Field] = []
```

* `username` - The Login field from the PAM User record.
* `dn` - The Distinguished Name from the PAM User record, if set.
* `new_password` - The new password that will be set.
* `prior_password` - The current password from the PAM User record.
* `new_private_key` - The new private key, if there was a private key rotation.
* `prior_private_key` - The current private key, if there was a private key rotation.
* `database` - The Connect Database from the PAM User record.
* `fields` - A list of custom fields and values from the PAM User record.
             Will be a list of `Field` instances.

#### user_and_domain

This method will split the username into user and domain, netbios, etc.
It will return a two item tuple.
The first item will be a Secret containing the username without the domain or netbios.
The second item is the domain or netbios.
If there was no domain or netbios, the second item will be `None`.

```python
my_user = SaasUser(
    username="jdoe@example.com"
)
my_user.user_and_domain()
# (Secret("jdoe"), "example.com")

my_user = SaasUser(
    username="example\\jdoe"
)
my_user.user_and_domain()
# (Secret("jdoe"), "example")

```

### config_record : Record

This will have an instance of Record. Record comes from Keeper Secrets Manager.

### provider_config : BaseModel; optional

If allowed, this attribute will have the credentials, and other values, used in the PAM Configuration.
The instance type depends on the configuration type.

#### AWS

```python
class AwsConfig(BaseModel):
    aws_access_key_id: Secret
    aws_secret_access_key: Secret
    region_names: List[str] = []
```

#### Azure

```python
class AzureConfig(BaseModel):
    subscription_id: Secret
    tenant_id: Secret
    application_id: Secret
    client_secret: Secret
    resource_groups: List[str] = []
    authority: Optional[str] = None
    graph_endpoint: Optional[str] = None
```

#### Domain Controller

```python
class DomainConfig(BaseModel):
    hostname: str
    port: int
    username: Secret
    dn: Secret
    password: Secret
    use_ssl: bool
```

#### Network

```python
class NetworkConfig(BaseModel):
    cidrs: List[str] = []
```

#### Google Cloud Provider

```python
class GcpConfig(BaseModel):
    service_account_key: Secret
    google_admin_email: Secret
    region_names: List[str] = []
    gcp_domain: str
```

#### OKTA

```python
class OktaConfig(BaseModel):
    okta_access_id: str
    okta_access_url: str
    okta_access_user: str
    okta_access_apikey: Secret
```

### force_fail : bool = False

This is a boolean value, default False, that can be used for testing. 

## Methods

### requirements

This is a list of Python modules required by the plugin.
To use, include in method in your plugin to override the default method.
If the modules are not installed, they will be installed into the Gateway's Python site-package.
If the module is used by the Gateway, and a version is specified, the module will not be updated.

For local testing, and syntax checking of your editor, place the following.

```python
try:  # pragma: no cover
    import some_sdk_module
    import another_sdk_module
except ImportError:  # pragma: no cover
    pass
```

The SaaS framework will check the modules in the requirements, which also loads them.
The `try/except` allows plugin to be loaded before the requirements have been installed, which
  allows the requirements to checked.



```python
@classmethod
def requirements(cls) -> List[str]:
    return [
      "requests",
      "some-module"
    ]
```

### config_schema

This is a list of fields that are required, and optional, in the SaaS Config record (Login).
To use, include in method in your plugin to override the default method.

```python
@classmethod
def config_schema(cls) -> List[dict]:
    return [
        SaasConfigItem(
            id="my_plugin_url",
            label="My Plugin URL",
            desc="The URL to my web service",
            type="url",
            required=True
        ),
        SaasConfigItem(
            id="my_plugin_token",
            label="Plugin Token",
            desc="The token",
            is_secret=True,
            required=True
        ),
    ]
```

#### SaasConfigItem Class

This class defined a parameter used by the plugin.

```python
# from kdnrm.saas_plugins import SaasConfigItem

class SaasConfigItem(BaseModel):
    id: str
    label: str
    desc: str
    is_secret: bool = False
    type: Optional[str] = "text"
    default_value: Optional[Any] = None
    enum_values: List[SaasConfigEnum] = []
    required: bool = False
    code: Optional[str] = None
    desc_code: Optional[str] = None
```

* `id` - The id for this field in the plugin. The value can be retrieved by self.get_config("<id>").
* `label` - This is the custom field label.
* `desc` - This is the default description.
* `is_secret` - A boolean flag.  Used for password, tokens, private keys. In the Vault, the value will be hidden.
* `type` - The data type for the field.
  * `text` - Any value is accepted, but now allowed to have linefeed in the text.
  * `multiline` - Any value is accepted and allowed to have linefeed in the text.
  * `url` - The value must be a URL format.
  * `int` - The value must be an integer number value. This would be a number without any decimals, such as a port number.
  * `number` - The value must be a number value. This includes integer and float type numbers.
  * `bool` - Boolean type value. The value must have a “truthy” format. Valid values are TRUE, Yes, On, 1, False, NO, OFF, 0 are valid values. It is case-insensitive.
  * `enum` - An enumeration of choice of values. If using an enumeration, the enum_values must be set to a list of acceptable values. These are instances of SaasConfigEnum.
  * `record` - UID of a record to pull into plugin. The UID needs to be in a whitelist on the PAM Configuration record.
* `default_value` - If the value is custom field value is blank or the field does not exist in the record, this value will be used.
* `enum_values` - A list of valid values for the enumeration, if the type is enum. It is a list of SaasConfigEnum. SaasConfigEnum attributes are:
  * `value` - The value that should be set in the custom field.
  * `desc` - Description of that that fields does in the plugin.
  * `code` - Use by Keeper for i18n of the enum description.
* `required` - Is this custom field required? It’s a boolean value.
* `code` - Use by Keeper for i18n of the label. 
* `desc_code` - Used by Keeper for i18n of the description.

#### SaasConfigEnum Class

This class is used with `SaasConfigItem` `enum_values`.
It defined an enumerated value.

```python
class SaasConfigEnum(BaseModel):
    value: str
    desc: Optional[str] = None,
    code: Optional[str] = None
```

* `value` - The value for the enumeration.
* `desc` - A decription of the value.
* `code` - Used by Keeper for i18n of the description.

Here is an example, of this class being used.

```python
@classmethod
def config_schema(cls) -> List[SaasConfigItem]:
    return [
        SaasConfigItem(
            id="rest_method",
            label="REST Method",
            desc="HTTP method. Either 'POST' or 'PUT'",
            code="gateway_kdnrm_saas_rest_method",
            type="enum",
            required=False,
            enum_values=[
                SaasConfigEnum(
                    value="POST",
                ),
                SaasConfigEnum(
                    value="PUT",
                ),
            ]
        )
    ]
```

### __init__()

This method is optional.
It does not need to be in your plugin, if you are not using it.
If overwritten, the `super()` method needs to called to set the attributes passed from the rotation.

```python
def __init__(self, 
             user: SaasUser, 
             config_record: Record, 
             provider_config: Optional[Any] = None, 
             force_fail: bool = False):
    super().__init__(user, config_record, provider_config, force_fail)
```

### can_rollback -> bool; property

This method determines if the SaaS rotation can be rollback.
To use, include in method in your plugin to override the default method.
This method can be used to check the remote site's configuration. 
Some site allow items like password history to be disabled, which would allow the ability to rollback passwords.

```python
@property
def can_rollback(self) -> bool:
    return True
```

### get_config(field_id, default_value) -> Any

This method is used to retrieve configuration values from the SaaS Config record (Login record with custom fields).

**Parameters:**
* `field_id` - The `id` from the `SaasConfigItem` defined in your `config_schema()`
* `default_value` - Optional fallback value if the field is missing or empty (defaults to None)

**Returns:** The configuration value, or the default value if not found.

**Value Resolution Order:**
1. Custom field value from the config record
2. `default_value` parameter passed to `get_config()`
3. `default_value` from the `SaasConfigItem` definition
4. `None`

**Example:**

```python
@classmethod
def config_schema(cls) -> List[SaasConfigItem]:
    return [
        SaasConfigItem(
            id="api_url",
            label="API URL",
            desc="The URL to the API endpoint",
            type="url",
            required=True
        ),
        SaasConfigItem(
            id="timeout",
            label="Request Timeout",
            desc="Timeout in seconds for API requests",
            type="int",
            default_value=30,
            required=False
        ),
    ]

def change_password(self):
    # Get required field - will raise exception if missing
    api_url = self.get_config("api_url")
    
    # Get optional field with default from schema (30)
    timeout = self.get_config("timeout")
    
    # Get optional field with override default
    retry_count = self.get_config("retry_count", default_value=3)
    
    # Use the values
    response = requests.post(
        api_url,
        json={"password": self.user.new_password.value},
        timeout=timeout
    )
```

**Note:** The value returned is already decrypted if the field is marked as `is_secret=True` in the schema.

### add_return_field(ReturnCustomField)

This method is used to create, or update, custom field in the PAM User record.
If all rotation were successful, the custom fields will be created or updated.
For example, if service or scheduled task rotations failed, and the entire rotation fails, the PAM User record
  will not be updated.
The method cannot handle complex values; it is limited to text data.

```python
def change_password(self):
  
    # Do stuff

    self.add_return_field(
        ReturnCustomField(
            label="Custom Field Label",
            value=Secret("Field Value")
        )
    )

```

An instance of `ReturnCustomField` is the only parameter for the method.

```python
class ReturnCustomField(BaseModel):
    label: str
    type: str = "text"
    value: Optional[Union[str, Secret]] = None
```

* `label` - The custom field label.
* `type` - The field type in the Vault. 
           The default is `text` which will show the value.
           The type can be set to `secret` to redact the value in the Vault.
* `value` - The value for the field. This can be either a Secret or str value.

### get_record_value(record_uid, field_type, label, single_value) ->  List[Any]

This method retrieves field values from another Keeper record by its UID. This is useful when your plugin needs access to additional credentials (like admin credentials) stored in separate records.

**Parameters:**
* `record_uid` - The UID of the desired record. Must be whitelisted in the PAM Configuration (see README.md "Additional record access in the plugin")
* `field_type` - Optional. The field type to match (e.g., "login", "password", "url"). Can be combined with `label`
* `label` - Optional. The field label to match (case-sensitive). Can be combined with `field_type`
* `single_value` - Boolean (default: True). If True, returns only the first value when a field contains multiple values

**Returns:** List of values matching the criteria. Returns empty list if no matches found.

**Important:** At least one of `field_type` or `label` must be specified, otherwise no values will be returned.

**Examples:**

```python
# Example 1: Get admin credentials from another record
# First, define the admin record UID in your config schema
@classmethod
def config_schema(cls) -> List[SaasConfigItem]:
    return [
        SaasConfigItem(
            id="admin_record_uid",
            label="Admin Credentials Record",
            desc="UID of the record containing admin credentials",
            type="record",
            required=True
        ),
    ]

def change_password(self):
    # Get the admin record UID from config
    admin_record_uid = self.get_config("admin_record_uid")
    
    # Get admin username (login field)
    admin_usernames = self.get_record_value(
        record_uid=admin_record_uid,
        field_type="login",
        single_value=True
    )
    admin_username = admin_usernames[0] if admin_usernames else None
    
    # Get admin password
    admin_passwords = self.get_record_value(
        record_uid=admin_record_uid,
        field_type="password",
        single_value=True
    )
    admin_password = admin_passwords[0] if admin_passwords else None
    
    # Use admin credentials to authenticate
    api_client = MyAPIClient(admin_username, admin_password)
    api_client.change_user_password(
        username=self.user.username.value,
        new_password=self.user.new_password.value
    )

# Example 2: Get a custom field by label
def change_password(self):
    api_token_record_uid = self.get_config("api_token_record_uid")
    
    # Get API token from custom field labeled "API Token"
    tokens = self.get_record_value(
        record_uid=api_token_record_uid,
        label="API Token",
        single_value=True
    )
    api_token = tokens[0] if tokens else None

# Example 3: Get multiple values (when single_value=False)
def change_password(self):
    config_record_uid = self.get_config("config_record_uid")
    
    # Get all URLs from the record
    all_urls = self.get_record_value(
        record_uid=config_record_uid,
        field_type="url",
        single_value=False  # Get all URL fields
    )
    
    # Try connecting to each URL until one works
    for url in all_urls:
        if self._test_connection(url):
            self.api_url = url
            break

# Example 4: Combine field_type and label for precise matching
def change_password(self):
    creds_record_uid = self.get_config("creds_record_uid")
    
    # Get specifically labeled password field
    passwords = self.get_record_value(
        record_uid=creds_record_uid,
        field_type="password",
        label="Service Account Password",
        single_value=True
    )
    service_password = passwords[0] if passwords else None
```

**Common Field Types:**
- `"login"` - Username/login field
- `"password"` - Password field  
- `"url"` - URL field
- `"text"` - Text custom field
- `"secret"` - Secret/hidden custom field
- `"multiline"` - Multi-line text field

**Security Note:** The record UID must be added to the PAM Configuration record's "SaaS Record Whitelist" custom field. Without whitelisting, access will be denied.

### get_record_fields(record_uid) -> List[Field]

This method retrieves all fields from a Keeper record as a list of `Field` objects. Use this when you need to access all fields from a record or don't know the exact field structure.

**Parameters:**
* `record_uid` - The UID of the desired record. Must be whitelisted in the PAM Configuration (see README.md "Additional record access in the plugin")

**Returns:** List of `Field` objects, each containing:
- `type` (str) - The field type (e.g., "login", "password", "text")
- `label` (str) - The field label
- `values` (List[Any]) - List of values for this field

**Important:** The record UID must be whitelisted in the PAM Configuration record.

**Examples:**

```python
# Example 1: Get all fields and iterate through them
def change_password(self):
    admin_record_uid = self.get_config("admin_record_uid")
    
    # Get all fields from the record
    fields = self.get_record_fields(record_uid=admin_record_uid)
    
    # Iterate through all fields
    for field in fields:
        Log.info(f"Field: {field.label} (type: {field.type})")
        Log.debug(f"  Values: {field.values}")
    
    # Find specific field by label
    api_token_field = next(
        (f for f in fields if f.label == "API Token"),
        None
    )
    
    if api_token_field:
        api_token = api_token_field.values[0] if api_token_field.values else None
    else:
        raise SaasException("API Token field not found in record")

# Example 2: Extract login credentials from all fields
def change_password(self):
    creds_record_uid = self.get_config("service_account_record_uid")
    fields = self.get_record_fields(record_uid=creds_record_uid)
    
    # Build a dictionary of credentials
    credentials = {}
    for field in fields:
        if field.type == "login":
            credentials['username'] = field.values[0] if field.values else None
        elif field.type == "password":
            credentials['password'] = field.values[0] if field.values else None
        elif field.label == "Server URL":
            credentials['server_url'] = field.values[0] if field.values else None
    
    # Use the credentials
    if not all([credentials.get('username'), credentials.get('password')]):
        raise SaasException("Missing required credentials in service account record")
    
    self._connect(
        server=credentials.get('server_url'),
        username=credentials['username'],
        password=credentials['password']
    )

# Example 3: Handle custom fields dynamically
def change_password(self):
    config_record_uid = self.get_config("extra_config_record_uid")
    fields = self.get_record_fields(record_uid=config_record_uid)
    
    # Create a mapping of custom field labels to values
    config_map = {}
    for field in fields:
        if field.type in ["text", "secret", "multiline"]:
            config_map[field.label] = field.values[0] if field.values else None
    
    # Access configuration dynamically
    region = config_map.get("Region", "us-east-1")
    environment = config_map.get("Environment", "production")
    
    Log.info(f"Using region: {region}, environment: {environment}")

# Example 4: Field structure exploration
from kdnrm.saas_type import Field

def change_password(self):
    record_uid = self.get_config("inspect_record_uid")
    fields = self.get_record_fields(record_uid=record_uid)
    
    # Field is a Pydantic BaseModel with these attributes:
    # - type: str
    # - label: str  
    # - values: List[Any]
    
    for field in fields:
        print(f"Type: {field.type}")
        print(f"Label: {field.label}")
        print(f"Values: {field.values}")
        print(f"First value: {field.values[0] if field.values else 'N/A'}")
        print("---")
```

**When to use `get_record_fields()` vs `get_record_value()`:**

Use `get_record_fields()` when:
- You need access to all fields in a record
- You don't know the exact field structure ahead of time
- You need to iterate through multiple custom fields
- You want to build a dynamic configuration from a record

Use `get_record_value()` when:
- You know the exact field type or label you need
- You only need one or two specific values
- You want cleaner, more direct access to a single value
- Performance matters (slightly faster for single field access)


### change_password()

This method is called to change the password.
To use, include in method in your plugin to override the default method.
Nothing is passed into the method.
It used the attribute `user` to get information about the user, password, old password, etc.

```python
    def change_password(self):

        Log.info("starting rotating of the Okta user")

        if "@" not in self.user.username.value:
            Log.error("the user is not an email address")
            raise Exception("The Okta user is not an email address.")

        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.rotate(
                prior_password=self.user.prior_password,
                new_password=self.user.new_password
            )
        )
```


### rollback_password()

This method is called to rollback/revert back to old password.
To use, include in method in your plugin to override the default method.
Similar to `change_password`, it uses the attribute `user` to get information about the user, password, old password, etc.

```python
def rollback_password(self):
    # Rollback stuff
```
