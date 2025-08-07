from __future__ import annotations

import re
import ssl
from typing import Any, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    ConflictError,
    NotFoundError
)

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, SaasConfigEnum, SaasConfigItem
from kdnrm.secret import Secret

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

# Constants
DEFAULT_SSL_VERIFY = True  # Change default
MAX_TOKEN_NAME_LENGTH = 256
API_TIMEOUT_SECONDS = 30
MAX_API_RETRIES = 3


class SaasPlugin(SaasPluginBase):

    name = "Elasticsearch Service Account Token"
    summary = "Create service account tokens in Elasticsearch for authentication."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self, 
        user, 
        config_record, 
        provider_config=None, 
        force_fail=False
    ):
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["elasticsearch"]

    @staticmethod
    def validate_elasticsearch_url(url: str) -> None:
        """Validate Elasticsearch URL format.
        
        Args:
            url: The Elasticsearch URL to validate
            
        Raises:
            SaasException: If the URL format is invalid
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL structure")
            if parsed.scheme not in ("http", "https"):
                raise ValueError("URL must use http or https")
        except Exception as e:
            raise SaasException(
                "Invalid Elasticsearch URL. Must be a valid http/https URL.",
                code="invalid_url"
            ) from e

    @staticmethod
    def should_verify_ssl(verify_ssl_config_value: str) -> bool:
        """Check if SSL verification should be enabled based on config value.
        
        Args:
            verify_ssl_config_value: The config value for SSL verification
            
        Returns:
            bool: True if SSL should be verified, False otherwise
        """
        return str(verify_ssl_config_value) == "True"

    @staticmethod
    def create_ssl_context(
        cert_content: Optional[str], 
        verify_ssl: bool
    ) -> Optional[ssl.SSLContext]:
        """Create SSL context if custom certificate and SSL verification enabled.
        
        Args:
            cert_content: The certificate content string
            verify_ssl: Whether SSL verification is enabled
            
        Returns:
            Optional[ssl.SSLContext]: SSL context if custom cert provided, None otherwise
            
        Raises:
            SaasException: If the SSL certificate content is invalid
        """
        if not verify_ssl:
            return None

        if not cert_content or not cert_content.strip():
            return None

        try:
            return ssl.create_default_context(cadata=cert_content.strip())
        except ssl.SSLError as e:
            Log.error(f"Invalid SSL certificate content: {e}")
            raise SaasException(
                f"Invalid SSL certificate: {e}",
                code="invalid_ssl_cert"
            ) from e

    @staticmethod
    def build_elasticsearch_client_config(
        hosts: list,
        verify_ssl: bool,
        cert_content: Optional[str] = None,
        api_key: Optional[str] = None,
        basic_auth: Optional[tuple] = None,
        request_timeout: int = API_TIMEOUT_SECONDS,
        max_retries: int = MAX_API_RETRIES
    ) -> dict:
        """Build configuration dictionary for Elasticsearch client.
        
        Args:
            hosts: List of Elasticsearch host URLs
            verify_ssl: Whether to verify SSL certificates
            cert_content: Optional SSL certificate content
            api_key: Optional API key for authentication
            basic_auth: Optional tuple of (username, password) for basic auth
            request_timeout: Request timeout in seconds
            max_retries: Maximum number of retries
            
        Returns:
            dict: Configuration dictionary for Elasticsearch client
            
        Raises:
            SaasException: If SSL certificate is invalid or auth config is invalid
        """
        if api_key and basic_auth:
            raise SaasException(
                "Cannot specify both API key and basic auth",
                code="invalid_auth_config"
            )

        if not api_key and not basic_auth:
            raise SaasException(
                "Must specify either API key or basic auth",
                code="missing_auth_config"
            )

        config = {
            "hosts": hosts,
            "verify_certs": verify_ssl,
            "request_timeout": request_timeout,
            "retry_on_timeout": True,
            "max_retries": max_retries,
        }

        if api_key:
            config["api_key"] = api_key
        elif basic_auth:
            config["basic_auth"] = basic_auth

        # Add SSL context if custom certificate is provided
        ssl_context = SaasPlugin.create_ssl_context(cert_content, verify_ssl)
        if ssl_context:
            config["ssl_context"] = ssl_context

        return config

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
                desc=(
                    "Elasticsearch API key for authentication. "
                    "Must have manage_service_account cluster privilege."
                ),
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
                desc=(
                    "The service name of the service account "
                    "(e.g., 'fleet-server', 'kibana')."
                ),
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
                default_value="True",
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
        return self.should_verify_ssl(self.get_config("verify_ssl"))

    def _validate_token_name(self, token_name: str) -> None:
        """Validate token name according to Elasticsearch requirements."""
        if not token_name or len(token_name) < 1 or len(token_name) > MAX_TOKEN_NAME_LENGTH:
            raise SaasException(
                f"Token name must be between 1 and {MAX_TOKEN_NAME_LENGTH} characters",
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

    def _validate_namespace(self, namespace: str) -> None:
        """Validate service account namespace format."""
        if not namespace:
            raise SaasException(
                "Namespace is required",
                code="namespace_required"
            )
        
        if not re.match(r'^[a-z][a-z0-9_-]*$', namespace):
            raise SaasException(
                "Invalid namespace format",
                code="invalid_namespace"
            )

    def _validate_service(self, service: str) -> None:
        """Validate service account service name format."""
        if not service:
            raise SaasException(
                "Service name is required",
                code="service_required"
            )
        
        if not re.match(r'^[a-z][a-z0-9_-]*$', service):
            raise SaasException(
                "Invalid service name format",
                code="invalid_service"
            )

    def _get_token_name_from_fields(self, fields: List[Any]) -> Optional[str]:
        """Extract token name from user fields with proper type handling."""
        for field in fields:
            if field.label == "token_name" and field.values:
                value = field.values[0]
                return (
                    value[0] if isinstance(value, list) and value else value
                )
        return None

    def _get_token_name(self) -> str:
        """Get the token name from the user fields."""
        token_name = self._get_token_name_from_fields(self.user.fields)
        
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
            self.validate_elasticsearch_url(elasticsearch_url)
            api_key = self.get_config("api_key")
            cert_content = self.get_config("ssl_content")

            Log.debug("Initializing Elasticsearch client")

            try:
                client_config = self.build_elasticsearch_client_config(
                    hosts=[elasticsearch_url],
                    verify_ssl=self.verify_ssl,
                    cert_content=cert_content,
                    api_key=api_key,
                    request_timeout=API_TIMEOUT_SECONDS,
                    max_retries=MAX_API_RETRIES
                )

                self._client = Elasticsearch(**client_config)
                self._client.ping()
                Log.debug("Successfully connected to Elasticsearch")

            except AuthenticationException as ae:
                raise SaasException(
                    "Authentication failed, make sure the credentials are correct",
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
        
        # Validate all inputs
        self._validate_namespace(namespace)
        self._validate_service(service)
        self._validate_token_name(token_name)
        Log.info(
            f"Creating service account token '{token_name}' "
            f"for {namespace}/{service}"
        )
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
        
        # Validate all inputs
        self._validate_namespace(namespace)
        self._validate_service(service)
        self._validate_token_name(token_name)
        Log.info(
            f"Deleting service account token '{token_name}' "
            f"for {namespace}/{service}"
        )
        self.client.security.delete_service_token(
            namespace=namespace,
            service=service,
            name=token_name
        )
        Log.info(f"Successfully deleted service account token '{token_name}'")
    

    def _extract_token_info(self, result: dict) -> str:
        """Extract token name and value from API response."""
        token_info = result.get("token")
        if not token_info:
            raise SaasException(
                "No token information returned from Elasticsearch",
                code="missing_token_info"
            )

        token_value = token_info.get("value")
        if not token_value:
            raise SaasException(
                "No token value returned from Elasticsearch",
                code="missing_token_value"
            )
        return token_value

    def _add_return_fields(self, token_value: str) -> None:
        """Add return fields to be stored in PAM."""
        self.add_return_field(
            ReturnCustomField(
                label="Service Account Token",
                type="secret",
                value=Secret(token_value)
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
        if self.client:
            pass
        else:
            Log.error("Failed to connect to Elasticsearch")
            raise SaasException(
                "Failed to connect to Elasticsearch",
                code="elasticsearch_connection_error"
            )
        try:
            self._delete_service_token()
        except NotFoundError:
            Log.info("Service account token not found, creating new one")
        try:
            result = self._create_service_token()
            token_value = self._extract_token_info(result)
            self._add_return_fields(token_value)

            Log.info(
                "Successfully created Elasticsearch service account token"
            )

        except SaasException:
            raise
        except Exception as e:
            Log.error(f"Unexpected error creating service account token: {e}")
            raise SaasException(
                f"Unexpected error: {e}", 
                code="unexpected_error"
            ) from e

    def rollback_password(self):
        """
        Service account tokens cannot be rolled back since they are created fresh each time.
        """
        Log.warning("Rollback not supported for service account tokens")
