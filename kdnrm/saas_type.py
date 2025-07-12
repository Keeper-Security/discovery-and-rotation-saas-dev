from __future__ import annotations
from kdnrm.secret import Secret
from pydantic import BaseModel, ConfigDict
from typing import Union, Optional, List, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from keeper_secrets_manager_core.dto.dtos import KeeperFile


class SaasConfigEnum(BaseModel):
    value: str
    desc: Optional[str] = None,
    code: Optional[str] = None,


class SaasConfigItem(BaseModel):
    id: str
    label: str
    desc: str
    is_secret: bool = False
    type: Optional[str] = "text"
    code: Optional[str] = None
    desc_code: Optional[str] = None
    default_value: Optional[Any] = None
    enum_values: List[SaasConfigEnum] = []
    required: bool = False


# The Field and SaaSUser are used to abstract information from the user.
# We only want to give the rotation the information it needs.
class Field(BaseModel):
    type: str
    label: str
    values: List[Any]


class File(BaseModel):
    title: str
    name: str
    content_type: Optional[str] = None
    content: Optional[bytes] = None


class SaasUser(BaseModel):
    username: Secret
    dn: Optional[Secret] = None
    new_password: Optional[Secret] = None
    prior_password: Optional[Secret] = None
    new_private_key: Optional[Secret] = None
    prior_private_key: Optional[Secret] = None
    database: Optional[str] = None
    fields: List[Field] = []
    files: Dict[str, Any] = {}

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def user_and_domain(self) -> (Secret, Optional[str]):
        user = self.username.value
        domain = None
        if "@" in user:
            user, domain = self.username.value.split("@", maxsplit=1)
        elif "\\" in user:
            domain, user = self.username.value.split("\\", maxsplit=1)
        return Secret(user), domain


class AwsConfig(BaseModel):
    aws_access_key_id: Secret
    aws_secret_access_key: Secret
    region_names: List[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)


class AzureConfig(BaseModel):
    subscription_id: Secret
    tenant_id: Secret
    application_id: Secret
    client_secret: Secret
    resource_groups: List[str] = []
    authority: Optional[str] = None
    graph_endpoint: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class DomainConfig(BaseModel):
    hostname: str
    port: int
    username: Secret
    dn: Secret
    password: Secret
    use_ssl: bool

    model_config = ConfigDict(arbitrary_types_allowed=True)


class NetworkConfig(BaseModel):
    cidrs: List[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)


# This structure is used to set/update custom fields on a pamUser record.
class ReturnCustomField(BaseModel):
    label: str
    type: str = "text"
    value: Optional[Union[str, Secret]] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


# This structure is used to attach a file to the pamUser record.
class ReturnAttachFile(BaseModel):
    title: str
    content: bytes
    name: Optional[str] = None
    content_type: Optional[str] = None
