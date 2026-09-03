from __future__ import annotations
from kdnrm.secret import Secret
from pydantic import BaseModel, ConfigDict

from typing import Union, Optional, List, Any


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
    label: Optional[str] = None
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
    aws_access_key_id: Optional[Secret] = None
    aws_secret_access_key: Optional[Secret] = None
    region_names: List[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)


class AzureConfig(BaseModel):
    subscription_id: Optional[Secret] = None
    tenant_id: Optional[Secret] = None
    application_id: Optional[Secret] = None
    client_secret: Optional[Secret] = None
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


class GcpConfig(BaseModel):
    service_account_key: Optional[Secret] = None
    google_admin_email: Optional[Secret] = None
    region_names: List[str] = []
    gcp_domain: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class GitHubConfig(BaseModel):
    github_token: Optional[Secret] = None
    github_owner: Optional[str] = None
    github_repos: List[str] = []
    github_scope: str = "repository"
    github_org_visibility: str = "all"
    github_base_url: str = "https://api.github.com"

    model_config = ConfigDict(arbitrary_types_allowed=True)


class OktaConfig(BaseModel):
    okta_access_id: Optional[str] = None
    okta_access_url: Optional[str] = None
    okta_access_user: Optional[str] = None
    okta_access_apikey: Optional[Secret] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


# This structure is used to set/update custom fields on a pamUser record.
class ReturnCustomField(BaseModel):
    label: str
    type: str = "text"
    value: Optional[Union[str, Secret]] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
