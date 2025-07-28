from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import SaasConfigItem, ReturnCustomField, SaasConfigEnum
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.secret import Secret
import re
from typing import List, TYPE_CHECKING, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, ConflictError, AuthenticationException
from integrations.elasticsearch.common.utils import (
    validate_elasticsearch_url,
    should_verify_ssl,
    build_elasticsearch_client_config
)

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

API_TIMEOUT = 30
MAX_RETRIES = 3


class SaasPlugin(SaasPluginBase):

    name = "Elasticsearch Service Account Token"
    summary = "Create service account tokens in Elasticsearch for authentication."
    readme = "README_elasticsearch_serviceaccount_token.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self, user, config_record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["elasticsearch"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="elasticsearch_url",
                label="Elasticsearch URL",
                desc="The URL to the Elasticsearch cluster.",
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="api_key",
                label="API Key",
                desc="Elasticsearch API key for authentication. Must have manage_service_account cluster privilege.",
                is_secret=True,
                required=True
            ),
            SaasConfigItem(
                id="namespace",
                label="Service Account Namespace",
                desc="The namespace of the service account (e.g., 'elastic').",
                required=True,
                default_value="elastic"
            ),
            SaasConfigItem(
                id="service",
                label="Service Account Service",
                desc="The service name of the service account (e.g., 'fleet-server', 'kibana').",
                required=True
            ),
            SaasConfigItem(
                id="verify_ssl",
                label="Verify SSL",
                desc=(
                    "Verify that the SSL certificate is valid: "
                    "'True' will validate certificates, "
                    "'False' will allow self-signed certificates."
                ),
                type="enum",
                required=False,
                default_value="False",
                enum_values=[
                    SaasConfigEnum(
                        value="False",
                        desc=(
                            "Do not validate the SSL certificate. "
                            "This will allow self-signed certificates."
                        )
                    ),
                    SaasConfigEnum(
                        value="True",
                        desc=(
                            "Validate the SSL certificate. "
                            "Self-signed certificates are not allowed."
                        )
                    ),
                ]
            ),
            SaasConfigItem(
                id="ssl_content",
                label="SSL Certificate Content",
                desc=(
                    "CA certificate content (.crt format). "
                    "Only required when 'Verify SSL' is set to 'True' "
                    "and using custom certificates."
                ),
                type="multiline",
                is_secret=True,
                required=False
            )
        ]

    @property
    def can_rollback(self) -> bool:
        """
        Service account tokens cannot be rolled back as they are created fresh each time.
        """
        return False

    @property
    def verify_ssl(self) -> bool:
        """
        Get the value of the verify_ssl configuration item.
        """
        return should_verify_ssl(self.get_config("verify_ssl"))

    def _validate_token_name(self, token_name: str) -> None:
        """Validate token name according to Elasticsearch requirements."""
        if not token_name or len(token_name) < 1 or len(token_name) > 256:
            raise SaasException(
                "Token name must be between 1 and 256 characters",
                code="invalid_token_name"
            )

        if token_name.startswith('_'):
            raise SaasException(
                "Token name cannot begin with an underscore",
                code="invalid_token_name"
            )

        if not re.match(r'^[a-zA-Z0-9_-]+$', token_name):
            raise SaasException(
                "Token name can only contain alphanumeric characters, dashes, and underscores",
                code="invalid_token_name"
            )

    def _get_token_name(self) -> str:
        """Get the token name from the user fields."""
        fields = self.user.fields
        token_name = None
        for field in fields:
            if field.label == "token_name":
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    token_name = value[0] if value else None
                else:
                    token_name = value
                break

        if not token_name:
            raise SaasException(
                "Token name is required",
                code="token_name_required"
            )
        return token_name

    @property
    def client(self) -> Elasticsearch:
        """
        Get or create the Elasticsearch client.
        """
        if self._client is None:
            elasticsearch_url = self.get_config("elasticsearch_url")
            validate_elasticsearch_url(elasticsearch_url)
            api_key = self.get_config("api_key")
            cert_content = self.get_config("ssl_content")

            Log.debug("Initializing Elasticsearch client")

            try:
                client_config = build_elasticsearch_client_config(
                    hosts=[elasticsearch_url],
                    verify_ssl=self.verify_ssl,
                    cert_content=cert_content,
                    api_key=api_key,
                    request_timeout=API_TIMEOUT,
                    max_retries=MAX_RETRIES
                )

                self._client = Elasticsearch(**client_config)
                self._client.ping()
                Log.debug("Successfully connected to Elasticsearch")

            except AuthenticationException as ae:
                raise SaasException(
                    "Authentication failed. Verify API key is correct",
                    code="authentication_failed"
                ) from ae
            except Exception as e:
                Log.error(f"Failed to connect to Elasticsearch: {e}")
                raise SaasException(
                    f"Failed to connect to Elasticsearch: {e}",
                    code="elasticsearch_connection_error"
                ) from e

        return self._client

    def _create_service_token(self) -> dict:
        """
        Create a service account token using the Elasticsearch SDK.
        """
        namespace = self.get_config("namespace")
        service = self.get_config("service")
        token_name = self._get_token_name()
        self._validate_token_name(token_name)
        Log.info(f"Creating service account token '{token_name}' for {namespace}/{service}")
        try:
            response = self.client.security.create_service_token(
                namespace=namespace,
                service=service,
                name=token_name
            )

            Log.info(f"Successfully created service account token '{token_name}'")
            return response

        except ConflictError as ce:
            raise SaasException(
                f"Service account token '{token_name}' already exists",
                code="token_already_exists"
            ) from ce
        except NotFoundError as ne:
            raise SaasException(
                f"Service account '{namespace}/{service}' not found",
                code="service_account_not_found"
            ) from ne
        except AuthenticationException as ae:
            raise SaasException(
                "Authentication failed. Verify API key is correct",
                code="authentication_failed"
            ) from ae
        except Exception as e:
            error_msg = str(e)
            Log.error(f"Elasticsearch error creating service account token: {error_msg}")
            raise SaasException(
                f"Failed to create service account token: {error_msg}",
                code="elasticsearch_error"
            ) from e

    def _delete_service_token(self) -> None:
        """Delete a service account token using the Elasticsearch SDK."""
        namespace = self.get_config("namespace")
        service = self.get_config("service")
        token_name = self._get_token_name()
        Log.info(f"Deleting service account token '{token_name}' for {namespace}/{service}")
        self.client.security.delete_service_token(
            namespace=namespace,
            service=service,
            name=token_name
        )
        Log.info(f"Successfully deleted service account token '{token_name}'")
    

    def _extract_token_info(self, result: dict) -> tuple[str, str]:
        """Extract token name and value from API response."""
        token_info = result.get("token")
        if not token_info:
            raise SaasException(
                "No token information returned from Elasticsearch",
                code="missing_token_info"
            )

        token_name = token_info.get("name")
        token_value = token_info.get("value")
        if not token_value:
            raise SaasException(
                "No token value returned from Elasticsearch",
                code="missing_token_value"
            )
        return token_name, token_value

    def _add_return_fields(self, token_name: str, token_value: str) -> None:
        """Add return fields to be stored in PAM."""
        self.add_return_field(
            ReturnCustomField(
                label="Service Account Token",
                type="secret",
                value=Secret(token_value)
            )
        )

        if token_name:
            self.add_return_field(
                ReturnCustomField(
                    label="Token Name",
                    value=Secret(token_name)
                )
            )

        namespace = self.get_config("namespace")
        service = self.get_config("service")
        self.add_return_field(
            ReturnCustomField(
                label="Service Account",
                value=Secret(f"{namespace}/{service}")
            )
        )

    def change_password(self):
        """
        Create a new service account token.
        """
        Log.info("Starting creation of Elasticsearch service account token")
        try:
            self._delete_service_token()
        except NotFoundError:
            Log.info("Service account token not found, creating new one")
        try:
            result = self._create_service_token()
            token_name, token_value = self._extract_token_info(result)
            self._add_return_fields(token_name, token_value)

            Log.info("Successfully created Elasticsearch service account token")

        except SaasException:
            raise
        except Exception as e:
            Log.error(f"Unexpected error creating service account token: {e}")
            raise SaasException(f"Unexpected error: {e}", code="unexpected_error") from e

    def rollback_password(self):
        """
        Service account tokens cannot be rolled back since they are created fresh each time.
        """
        Log.warning("Rollback not supported for service account tokens")
        pass
