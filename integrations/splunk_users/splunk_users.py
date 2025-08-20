import ssl
from typing import List, Optional
from urllib.parse import urlparse

from splunklib import client
from splunklib.binding import HTTPError
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem, SaasConfigEnum

class SaasPlugin(SaasPluginBase):
    """Splunk User Password Rotation Plugin."""

    name = "Splunk User Password Rotation"
    summary = "Change a user password in Splunk."
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
        self.user = user
        self.config_record = config_record
        self._service = None
        self._can_rollback = False

    @classmethod
    def requirements(cls) -> List[str]:
        return ["splunk-sdk"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="splunk_host",
                label="Splunk Host URL",
                desc="Splunk management port URL (e.g., https://example.com:8089).",
                type="url",
                required=True,
            ),
            SaasConfigItem(
                id="username",
                label="Splunk Admin Username",
                desc="Splunk admin user to authenticate the SDK client.",
                required=True,
            ),
            SaasConfigItem(
                id="password",
                label="Splunk Admin Password",
                desc="Splunk admin password.",
                type="secret",
                is_secret=True,
                required=True,
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
                        desc="Do not validate the SSL certificate."
                    ),
                    SaasConfigEnum(
                        value="True",
                        desc="Validate the SSL certificate."
                    ),
                ]
            ),
            SaasConfigItem(
                id="ssl_content",
                label="SSL Certificate Content",
                desc=(
                    "CA certificate content"
                    "Only required when 'Verify SSL' is set to 'True'."
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
        """Verify SSL for the Splunk client."""
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
        cleaned = (cert_content.replace('\n', '')
                   .replace('\r', '')
                   .replace(' ', '')
                   .replace('\t', ''))
        
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
            Log.error("SSL certificate content does not start with "
                     "'-----BEGIN CERTIFICATE-----'")
            raise SaasException(
                "Invalid SSL certificate format: "
                "Missing '-----BEGIN CERTIFICATE-----' header",
                code="invalid_ssl_cert_format"
            )
            
        if not stripped_content.endswith("-----END CERTIFICATE-----"):
            Log.error("SSL certificate content does not end with "
                     "'-----END CERTIFICATE-----'")
            raise SaasException(
                "Invalid SSL certificate format: "
                "Missing '-----END CERTIFICATE-----' footer",
                code="invalid_ssl_cert_format"
            )

        try:
            Log.debug("Creating SSL context with provided certificate")
            return ssl.create_default_context(cadata=stripped_content)
        except ssl.SSLError as e:
            Log.error(f"Invalid SSL certificate content: {e}")
            raise SaasException(
                f"Invalid SSL certificate: {e}",
                code="invalid_ssl_cert"
            ) from e

    @staticmethod
    def validate_splunk_url(url: str) -> None:
        """Validate Splunk URL format.
        
        Args:
            url: The Splunk URL to validate
            
        Raises:
            SaasException: If the URL format is invalid
        """
        if not url or not url.strip():
            raise SaasException(
                "Splunk URL cannot be empty",
                code="invalid_url"
            )
            
        try:
            parsed = urlparse(url.strip())
            
            if not parsed.scheme:
                raise SaasException(
                    "Invalid Splunk URL: scheme is required (http or https)",
                    code="invalid_url"
                )
                
            if parsed.scheme not in ("http", "https"):
                raise SaasException(
                    "Invalid Splunk URL: scheme must be http or https",
                    code="invalid_url"
                )
                
            if not parsed.hostname:
                raise SaasException(
                    "Invalid Splunk URL: hostname is required",
                    code="invalid_url"
                )
                
        except SaasException:
            # Re-raise SaasExceptions as-is
            raise
        except Exception as e:
            raise SaasException(
                f"Invalid Splunk URL format: {str(e)}",
                code="invalid_url"
            ) from e



    @property
    def service(self) -> client.Service:
        """Initialize or return the Splunk SDK Service client."""
        if self._service is None:
            try:
                splunk_host = self.get_config("splunk_host")
                self.validate_splunk_url(splunk_host)
                
                # Parse URL to get components
                parsed_url = urlparse(splunk_host)
                host = parsed_url.hostname
                port = (parsed_url.port or 
                        (8089 if parsed_url.scheme == "https" else 8089))
                scheme = parsed_url.scheme
                
                # Get SSL certificate content if provided
                cert_content = self.get_config("ssl_content")
                # Get admin credentials for connection
                admin_username = self.get_config("username")
                admin_password = self.get_config("password")
                
                # Prepare connection arguments
                connect_args = {
                    "host": host,
                    "port": port,
                    "username": admin_username,
                    "password": admin_password,
                    "scheme": scheme,
                    "verify": self.verify_ssl
                }
                
                # Handle SSL certificate content using the working approach
                if cert_content and cert_content.strip():
                    Log.debug("Custom SSL certificate provided")
                    try:
                        # Create SSL context with custom certificate
                        ssl_context = self.create_ssl_context(cert_content, True)
                        if ssl_context:
                            Log.info("Custom SSL certificate validated successfully")
                            # Use the context parameter as in your working code
                            connect_args["context"] = ssl_context
                            Log.debug("Added custom SSL context to connection args")
                        else:
                            Log.warning("Failed to create SSL context, "
                                       "using standard verification")
                            
                    except Exception as cert_error:  # pylint: disable=broad-except
                        Log.error(f"SSL certificate processing failed: {cert_error}")
                        Log.warning("Using standard SSL verification")
                else:
                    Log.debug("No custom SSL certificate provided")
                    if not self.verify_ssl:
                        Log.warning("SSL verification is disabled - "
                                   "connection may be insecure")
                
                # Connect to Splunk using the working approach
                self._service = client.connect(**connect_args)
                Log.debug("Connected to Splunk management port.")
            except HTTPError as he:
                if he.status == 401:
                    Log.error(f"Authentication failed connecting to Splunk: {he}")
                    raise SaasException(
                        "Authentication failed. Invalid credentials."
                    ) from he
                elif he.status == 400:
                    Log.error(f"Bad request when connecting to Splunk: {he}")
                    raise SaasException("Bad request when connecting to Splunk.") from he
            except Exception as e:
                Log.error(f"Failed to connect to Splunk: {e}")
                raise SaasException(f"Failed to connect to Splunk: {e}") from e
        return self._service

    @property
    def can_rollback(self) -> bool:
        return self._can_rollback

    @can_rollback.setter
    def can_rollback(self, val: bool):
        self._can_rollback = val

    def _verify_user_exists(self):
        try:
            _ = self.service.users[self.user.username.value]
            Log.debug(f"User '{self.user.username.value}' exists in Splunk.")
            self.can_rollback = True
        except KeyError as exc:
            Log.error(f"User '{self.user.username.value}' "
                     f"does not exist in Splunk.")
            raise SaasException(
                f"User '{self.user.username.value}' does not exist in Splunk."
            ) from exc
        except Exception as e:
            Log.error(f"Error verifying user existence: {e}")
            raise SaasException(
                f"Failed to verify user existence: {e}"
            ) from e

    def _change_user_password(self, password: Secret):
        username = self.user.username.value
        Log.info(f"Changing password for Splunk user: {username}")

        self._verify_user_exists()

        try:
            user_entity = self.service.users[username]
            user_entity.update(password=password.value)
            Log.info(f"Password changed successfully for user: {username}")
            self._service = None
        except HTTPError as he:
            if he.status == 403:
                Log.error(f"Authorization failed changing password for "
                         f"user {username}: {he}")
                raise SaasException(
                    "Authorization failed. Insufficient permissions to "
                    "change user password."
                ) from he
            elif he.status == 400:
                self.can_rollback = True
                Log.error(f"Bad request when changing password for "
                         f"user {username}: {he}")
                raise SaasException("Invalid password change request.") from he
            else:
                Log.error(f"HTTP error changing password for "
                         f"user {username}: {he}")
                raise SaasException(f"Failed to change password: {he}") from he
        except Exception as e:
            self.can_rollback = True
            Log.error(f"Unexpected error changing password for "
                     f"user {username}: {e}")
            raise SaasException(f"Failed to change password: {e}") from e

    def change_password(self):
        if self.user.new_password is None:
            raise SaasException(
                "Cannot change password. No new password provided."
            )
        
        if self.service is None:
            raise SaasException(
                "Cannot change password. Service is not initialized."
            )

        Log.info("Starting password change for Splunk user")
        self._change_user_password(self.user.new_password)
        Log.debug(f"Password change completed successfully for "
                 f"user {self.user.username.value}")

    def rollback_password(self):
        if self.user.prior_password is None:
            raise SaasException(
                "Cannot rollback password. No prior password available."
            )

        Log.info("Rolling back password change for Splunk user")
        assert self.user.prior_password is not None  # for type checkers
        self._change_user_password(self.user.prior_password)
        Log.debug(f"Password rollback completed successfully for "
                 f"user {self.user.username.value}")