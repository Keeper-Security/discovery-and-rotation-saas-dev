from __future__ import annotations
import ssl
from typing import Any, List, Optional, TYPE_CHECKING
from urllib.parse import ParseResult, urlparse

from opensearchpy import OpenSearch
from opensearchpy.exceptions import (
    AuthenticationException,
    AuthorizationException,
    NotFoundError,
    RequestError
)

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import  SaasConfigItem, SaasConfigEnum

if TYPE_CHECKING:  # pragma: no cover
    from keeper_secrets_manager_core.dto.dtos import Record
    from kdnrm.saas_type import SaasUser

# Constants
API_TIMEOUT = 30
DEFAULT_PORT = 9200
API_ENDPOINT = "/_plugins/_security/api/internalusers"

class SaasPlugin(SaasPluginBase):
    """OpenSearch User Password Rotation Plugin."""

    name = "OpenSearch User"
    summary = "Rotate user password in OpenSearch cluster."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self,
        user: SaasUser,
        config_record: Record,
        provider_config: Any = None,
        force_fail: bool = False
    ) -> None:
        """Initialize the OpenSearch plugin.
        
        Args:
            user: The SaaS user object containing user information
            config_record: Configuration record with OpenSearch credentials
            provider_config: Optional provider-specific configuration
            force_fail: Whether to force failure for testing purposes
        """
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None
        self._can_rollback = False

    @classmethod
    def requirements(cls) -> List[str]:
        """Return required Python packages for this plugin.
        
        Returns:
            List of required package names
        """
        return ["opensearch-py"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        """Return the configuration schema for this plugin.
        
        Returns:
            List of configuration items required for OpenSearch connection
        """
        return [
            SaasConfigItem(
                id="opensearch_url",
                label="OpenSearch URL",
                desc=(
                    "The URL to the OpenSearch cluster "
                    "(e.g., https://opensearch.example.com:9200)."
                ),
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="admin_username",
                label="Admin Username",
                desc="Username for the OpenSearch admin user.",
                type="text",
                required=True
            ),
            SaasConfigItem(
                id="admin_password",
                label="Admin Password",
                desc="Password for the OpenSearch admin user.",
                type="secret",
                is_secret=True,
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
                    "CA certificate content in PEM format. "
                    "Only required when 'Verify SSL' is set to 'True' "
                    "and using custom certificates."
                ),
                type="multiline",
                is_secret=True,
                required=False
            )
        ]

    @staticmethod
    def should_verify_ssl(verify_ssl_config_value: str) -> bool:
        """Check if SSL verification should be enabled based on config value.
        
        Args:
            verify_ssl_config_value: The config value for SSL verification
            
        Returns:
            bool: True if SSL should be verified, False otherwise
        """
        return str(verify_ssl_config_value) == "True"

    @property
    def verify_ssl(self) -> bool:
        """Verify SSL for the OpenSearch client."""
        verify_ssl_value = self.get_config("verify_ssl")
        return self.should_verify_ssl(verify_ssl_value)

    @staticmethod
    def fix_certificate_format(cert_content: str) -> str:
        """Fix certificate format by ensuring proper line breaks.
        
        Args:
            cert_content: Raw certificate content
            
        Returns:
            Properly formatted certificate content
        """
        # Remove all whitespace and normalize
        cleaned = cert_content.replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')
        
        # Find certificate boundaries
        begin_marker = "-----BEGINCERTIFICATE-----"
        end_marker = "-----ENDCERTIFICATE-----"
        
        if begin_marker not in cleaned or end_marker not in cleaned:
            return cert_content  # Return original if markers not found
        
        # Extract the certificate data between markers
        start_idx = cleaned.find(begin_marker) + len(begin_marker)
        end_idx = cleaned.find(end_marker)
        cert_data = cleaned[start_idx:end_idx]
        
        # Format with proper line breaks (64 characters per line)
        formatted_lines = []
        for i in range(0, len(cert_data), 64):
            formatted_lines.append(cert_data[i:i+64])
        
        # Reconstruct properly formatted certificate
        formatted_cert = "-----BEGIN CERTIFICATE-----\n"
        formatted_cert += "\n".join(formatted_lines)
        formatted_cert += "\n-----END CERTIFICATE-----"
        
        return formatted_cert

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
            Log.debug("SSL verification disabled, skipping SSL context creation")
            return None

        if not cert_content or not cert_content.strip():
            Log.debug("No SSL certificate content provided")
            return None

        # Fix certificate format if needed
        stripped_content = cert_content.strip()
        
        # Check if certificate contains valid headers and footers
        has_begin_marker = "-----BEGIN CERTIFICATE-----" in stripped_content
        has_end_marker = "-----END CERTIFICATE-----" in stripped_content
        
        if has_begin_marker and has_end_marker:
            Log.debug("Certificate has valid markers - normalizing format")
            stripped_content = SaasPlugin.fix_certificate_format(stripped_content)
            Log.debug("Certificate format normalized")
        
        # Check if certificate has proper format after normalization
        if not stripped_content.startswith("-----BEGIN CERTIFICATE-----"):
            Log.error("SSL certificate content does not start with '-----BEGIN CERTIFICATE-----'")
            raise SaasException(
                "Invalid SSL certificate format: Missing '-----BEGIN CERTIFICATE-----' header",
                code="invalid_ssl_cert_format"
            )
            
        if not stripped_content.endswith("-----END CERTIFICATE-----"):
            Log.error("SSL certificate content does not end with '-----END CERTIFICATE-----'")
            raise SaasException(
                "Invalid SSL certificate format: Missing '-----END CERTIFICATE-----' footer",
                code="invalid_ssl_cert_format"
            )

        try:
            Log.debug("Creating SSL context with provided certificate")
            return ssl.create_default_context(cadata=stripped_content)
        except ssl.SSLError as e:
            Log.error(f"Invalid SSL certificate content: {e}")
            Log.error(f"Certificate content preview: {stripped_content[:200]}...")
            raise SaasException(
                f"Invalid SSL certificate: {e}",
                code="invalid_ssl_cert"
            ) from e

    @staticmethod
    def validate_opensearch_url(url: str) -> ParseResult:
        """Validate OpenSearch URL format.
        
        Args:
            url: The OpenSearch URL to validate
            
        Returns:
            ParseResult: Parsed URL components
            
        Raises:
            SaasException: If the URL format is invalid
        """
        if not url or not url.strip():
            raise SaasException(
                "OpenSearch URL cannot be empty",
                code="invalid_url"
            )
            
        try:
            parsed = urlparse(url.strip())
            
            if not parsed.scheme:
                raise SaasException(
                    "Invalid OpenSearch URL: scheme is required (http or https)",
                    code="invalid_url"
                )
                
            if parsed.scheme not in ("http", "https"):
                raise SaasException(
                    "Invalid OpenSearch URL: scheme must be http or https",
                    code="invalid_url"
                )
                
            if not parsed.hostname:
                raise SaasException(
                    "Invalid OpenSearch URL: hostname is required",
                    code="invalid_url"
                )
                
            return parsed
            
        except SaasException:
            # Re-raise SaasExceptions as-is
            raise
        except Exception as e:
            raise SaasException(
                f"Invalid OpenSearch URL format: {str(e)}",
                code="invalid_url"
            ) from e

    @property
    def client(self) -> OpenSearch:
        """Get or create the OpenSearch client.
        
        Returns:
            Configured OpenSearch client instance
            
        Raises:
            SaasException: If client creation fails
        """
        if self._client is None:
            Log.debug("Creating OpenSearch client")
            
            try:
                url = self.get_config("opensearch_url")
                admin_username = self.get_config("admin_username")
                admin_password = self.get_config("admin_password")
                verify_ssl = self.verify_ssl
                
                # Parse URL to extract components
                parsed_url = self.validate_opensearch_url(url)
                host = parsed_url.hostname
                port = parsed_url.port or DEFAULT_PORT
                use_ssl = parsed_url.scheme == "https"
                
                ssl_context = SaasPlugin.create_ssl_context(self.get_config("ssl_content"), self.verify_ssl)
                # Create OpenSearch client
                client_kwargs = {
                    "hosts": [{"host": host, "port": port}],
                    "http_auth": (admin_username, admin_password),
                    "use_ssl": use_ssl,
                    "timeout": API_TIMEOUT,
                    "connection_class": None
                }
                if ssl_context:
                    client_kwargs["ssl_context"] = ssl_context
                else:
                    client_kwargs["verify_certs"] = verify_ssl

                self._client = OpenSearch(**client_kwargs)  
                self._client.info()

            except Exception as e:
                Log.error(f"Failed to create OpenSearch client: {e}")
                raise SaasException(
                    f"Failed to create OpenSearch client: {str(e)}"
                ) from e

        return self._client

    def _validate_configuration(self) -> None:
        """Validate all configuration parameters.
        
        Raises:
            SaasException: If any configuration parameter is invalid
        """
        Log.debug("Validating OpenSearch configuration parameters")
        
        try:
            # Validate URL format using centralized validation
            url = self.get_config("opensearch_url")
            self.validate_opensearch_url(url)
            
            # Validate required fields
            admin_username = self.get_config("admin_username")
            if not admin_username or not admin_username.strip():
                raise SaasException("Admin Username cannot be empty")
            
            admin_password = self.get_config("admin_password")
            if not admin_password or not admin_password.strip():
                raise SaasException("Admin Password cannot be empty")
            
            Log.debug("All OpenSearch configuration parameters are valid")
            
        except SaasException:
            # Re-raise SaasExceptions as-is (including URL validation errors)
            raise
        except Exception as e:
            Log.error(f"Configuration validation failed: {e}")
            raise SaasException(f"Configuration validation failed: {str(e)}") from e


    def _is_user_present(self, username: str) -> bool :
        """Get user details from OpenSearch.
        
        Args:
            username: The username to retrieve
            
        Returns:
            User details dictionary
            
        Raises:
            SaasException: If user retrieval fails
        """
        try:
            Log.debug(f"Retrieving user details for: {username}")
            
            self.client.transport.perform_request(
                "GET",
                f"{API_ENDPOINT}/{username}"
            )

            Log.debug(f"Successfully retrieved user details for: {username}")
            return True
            
        except NotFoundError as nfe:
            raise SaasException(f"User '{username}' not found") from nfe
        except AuthenticationException as e:
            raise SaasException(f"Authentication failed: {str(e)}") from e
        except AuthorizationException as e:
            raise SaasException(f"Authorization failed: {str(e)}") from e
        except Exception as e:
            Log.error(f"Failed to get user details: {e}")
            raise SaasException(f"Failed to get user details: {str(e)}") from e

    def _update_user_password(self, username: str, new_password: str) -> None:
        """Update user password in OpenSearch.
        
        Args:
            username: The username to update
            new_password: The new password
            
        Raises:
            SaasException: If password update fails
        """
        try:
            Log.debug(f"Updating password for user: {username}")

            if not self._is_user_present(username):
                raise SaasException(f"User '{username}' not found")

            update_payload = {
                "password": new_password
            }

            response = self.client.transport.perform_request(
                "PUT",
                f"{API_ENDPOINT}/{username}",
                body=update_payload
            )

            if response.get("status") != "OK":
                raise SaasException(f"Password update failed: {response}")

            Log.info(f"Successfully updated password for user: {username}")
            
        except AuthenticationException as e:
            raise SaasException(f"Authentication failed: {str(e)}") from e
        except AuthorizationException as e:
            raise SaasException(f"Authorization failed: {str(e)}") from e
        except RequestError as re:
            raise SaasException(f"Request failed: {str(re)}") from re
        except Exception as e:
            Log.error(f"Failed to update user password: {e}")
            raise SaasException(f"Failed to update user password: {str(e)}") from e

    @property
    def can_rollback(self) -> bool:
        """Check if password rollback is supported.
        
        OpenSearch passwords cannot be rolled back as the old password
        hash cannot be restored once changed.
        
        Returns:
            False - rollback is not supported
        """
        return self._can_rollback

    def change_password(self) -> None:
        """Rotate the user password in OpenSearch.
        Raises:
            SaasException: If any step of the rotation process fails
        """
        Log.info("Starting OpenSearch user password rotation")

        self._validate_configuration()
        if self.client is None:
            raise SaasException("Failed to create OpenSearch client")

        try:
            username = self.user.username
            if not username or not username.value.strip():
                raise SaasException("Username field is required but not found")
            
            # Get new password
            new_password = self.user.new_password
            if not new_password:
                raise SaasException("New password is required")
                
            self._can_rollback = True
            # Update password in OpenSearch
            self._update_user_password(username.value, new_password.value)

            Log.info("OpenSearch user password rotation completed successfully")
            
        except Exception as e:
            Log.error(f"OpenSearch password rotation failed: {e}")
            raise SaasException(f"Password rotation failed: {str(e)}") from e

    def rollback_password(self) -> None:
        """
        Rollback the password change for the OpenSearch user.
        """
        Log.info("Rollback requested for OpenSearch user password")
        try:
            if self.user.prior_password is None:
                raise SaasException("Prior password is required for rollback")

            username = self.user.username.value
            self._update_user_password(username, self.user.prior_password.value)
        except Exception as e:
            Log.error(f"Failed to rollback password: {e}")
            raise SaasException(f"Failed to rollback password: {str(e)}") from e

