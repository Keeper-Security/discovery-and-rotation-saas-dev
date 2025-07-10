from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from oci.config import validate_config
from oci.identity_domains import IdentityDomainsClient
from oci.exceptions import ServiceError
import re
from typing import List, Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):

    name = "Oracle Identity Domain User"
    summary = "Change a user password in Oracle Identity Domain."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self,
                 user: SaasUser,
                 config_record: Record,
                 provider_config: Any = None,
                 force_fail: bool = False):

        super().__init__(user, config_record, provider_config, force_fail)

        self._oci_config = None
        self._client = None
        self._identity_domain_id = None
        self._identity_domain_user_id = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["oci"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="domain_url",
                label="Domain URL",
                desc='Domain URL. Found in Identity & Security -> Domains -> Domain.',
                required=True,
            ),
            SaasConfigItem(
                id="user",
                label="Admin OCID",
                desc='The "user" part of the OCI config. Starts with "ocid1.user..."',
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="fingerprint",
                label="Public Key Fingerprint",
                desc='The "fingerprint" part of the OCI config. Looks like "XX:XX:XX....."',
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="key_content",
                label="Private Key Content",
                desc='The content of the Private Key PEM file.',
                type="multiline",
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="tenancy",
                label="Tenancy OCID",
                desc='The "tenancy" part of the OCI config. Looks like "ocid1.tenancy..."',
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="region",
                label="Home Region",
                desc='The "region" part of the OCI config. Looks like "us-sanjose-1"',
                is_secret=False,
                required=True,
            ),
        ]

    @property
    def oci_config(self):
        if self._oci_config is None:

            Log.debug("build OCI config")

            # There are 2 version of the ocid, so ocid1 amd ocid2 are possible
            # The realms are
            #  * oc1 - Commercial realm
            #  * oc2 - Government Cloud realm
            #  * oc3 - Federal Government Cloud realm
            user = self.get_config("user")
            if re.match(r"ocid\d\.user.oc\d\.\.", user) is None:
                raise SaasException("The format of the Admin OCID field does is not valid. "
                                    "It should start with 'ocid#.user.oc#..")

            key_content = self.get_config("key_content")
            # Oracle likes to put this at the end of cert, we need to remove it if it exists.
            key_content = key_content.replace("OCI_API_KEY", "").strip()
            if (not key_content.startswith("-----BEGIN PRIVATE KEY-----")
                    or not key_content.endswith("-----END PRIVATE KEY-----")):
                raise SaasException("The value in Private Key Content field does not appear to be the "
                                    "content of the private key PEM file.")

            fingerprint = self.get_config("fingerprint")
            if re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2}){15}$', fingerprint) is None:
                raise SaasException("The value in Public Key Fingerprint field does not appear valid. "
                                    "It should look like 'xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx'")

            tenancy = self.get_config("tenancy")
            if re.match(r"ocid\d\.tenancy.oc\d\.\.", tenancy) is None:
                raise SaasException("The format of the Tenancy OCID field does is not valid. "
                                    "It should start with 'ocid#.tenancy.oc#..")

            self._oci_config = {
                "user": user,
                "key_content": key_content,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": self.get_config("region"),
            }
            validate_config(self._oci_config)
        return self._oci_config

    @property
    def client(self) -> IdentityDomainsClient:
        if self._client is None:
            Log.debug("get identify domain client")
            domain_url = self.get_config("domain_url")
            self._client = IdentityDomainsClient(self.oci_config, service_endpoint=domain_url)

        return self._client

    @property
    def identity_domain_user_id(self):
        if self._identity_domain_user_id is None:

            Log.debug("get identify domain user id")

            user_filter = f'userName eq "{self.user.username.value}"'

            user, domain = self.user.user_and_domain
            if domain is not None:
                user_filter = f'emails.value eq "{self.user.username.value}"'

            Log.debug("get the identity domain User")
            res = self.client.list_users(
                filter=user_filter,
                attributes=["id", "userName"],
                limit=1
            )
            self._identity_domain_user_id = res.data.resources[0].id

        return self._identity_domain_user_id

    @property
    def can_rollback(self) -> bool:

        Log.debug("checking password history count to see if can rollback")

        res = self.client.list_password_policies(
            attributes=['passwordHistoryCount', 'name', 'description']
        )
        if res.data.resources:
            max_count = 0
            for policy in res.data.resources:
                if policy.num_passwords_in_history is not None and policy.num_passwords_in_history > max_count:
                    max_count = policy.password_history_count
            return max_count == 0
        return False

    def update_password(self, password: Secret):

        Log.debug("updating the password")

        try:
            res = self.client.patch_user(
                user_id=self.identity_domain_user_id,
                patch_op={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [
                        {
                            "op": "replace",
                            "path": "password",
                            "value": password.value
                        }
                    ]
                }
            )
        except ServiceError as err:
            Log.error(f"could not change password: {err}")
            if err.status == 404:
                Log.error("the user was not found")
                raise SaasException("The user was not found in the Identity Domain.")
            raise SaasException(f"Could not change password, received the following error: {err}")

    def change_password(self):
        """
        Change the password for the Oracle Identity Domain User Plugin user.
        This method connects to the Oracle Identity Domain User Plugin account using the admin credentials
        and changes the password for the specified user.
        """
        Log.info("Changing password for Oracle Identity Domain User Plugin")
        self.update_password(password=self.user.new_password)
        Log.info("password rotate was successful")

    def rollback_password(self):
        """
        Rollback the password change for the Oracle Identity Domain User Plugin user.
        This method is called to revert the password change if needed.
        """

        if self.user.prior_password is None:
            raise SaasException("Cannot rollback password. The current password is not set.")

        Log.info("Rolling back password change for Oracle Identity Domain User Plugin")
        self.update_password(password=self.user.prior_password)
        Log.info("rolling back password was successful")
