# Secret

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

## value_strip -> Any; propert

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

if TYPE_CHECKING:
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record
    

class SaasPluginBase:
    
    name = "NA"
    
    @classmethod
    def requirements(cls) -> List[str]:
        return []
    
    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return []
    
    def __init__(self, 
                 user: SaasUser, 
                 config_record: Record, 
                 provider_config: Optional[Any] = None):
        self.user = user
        self.config_record = config_record
        self.name = self.__class__.name
        
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
    username="jdoe@exmaple.com"
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

If allowed, this attribute will have the credentials used in the configuration.
The instance type depends on the configuration type.

#### AWS

```python
class AwsConfig(BaseModel):
    aws_access_key_id: Secret
    aws_secret_access_key: Secret
    region_names: List[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)
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

### force_fail : bool = False

This is a boolean value, default False, that can be used for testing. 

## Methods

### requirements

This is a list of Python modules required by the plugin.
To use, include in method in your plugin to override the default method.
If the modules are not installed, they will be installed into the Gateway's Python site-package.
If the module is used by the Gateway, and a version is specified, the module will not be updated.


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
            id="my_plikgin_token",
            label="Plugin Token",
            desc="The token"
            type="password",
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
    type: Optional[str] = "text"
    default_value: Optional[Any] = None
    enum_values: List[SaasConfigEnum] = []
    required: bool = False
    code: Optional[str] = None
    desc_code: Optional[str] = None
```

* `id` - The id for this field in the plugin. The value can be retrieved by self.get_conifg("<id>").
* `label` - This is the custom field label.
* `desc` - This is the default description.
* `type` - The data type for the field.
  * `secret` - Used for password, tokens, private keys. In the Vault, the value will be hidden.
  * `text` - Any value is accepted.
  * `url` - The value must be an a URL format.
  * `int` - The value must be an integer number value. This would be a number without any decimals, such as a port number.
  * `number` - The value must be a number value. This includes integer and float type numbers.
  * `bool` - Boolean type value. The value must have a “truthy” format. Valid values are TRUE, Yes, On, 1, False, NO, OFF, 0 are valid values. It is case insensitive.
  * `enum` - An enumeration of choice of values. If using an enumeration, the enum_values must be set to a list of acceptable values. These are instances of SaasConfigEnum.
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
    code: Optional[str] = None,
```

* `value` - The value for the enumeration.
* `desc` - A decription of the value.
* `code` - Used by Keeper for i18n of the description.

Here is an exmaple, of this class being used.

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

This method can is optional.
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
            raise SaasException("The Okta user is not an email address.",
                                code="gateway_kdnrm_saas_okta_user_not_email")

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











