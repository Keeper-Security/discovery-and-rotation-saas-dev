import os
import ssl
import tempfile
from typing import List, Optional

import jwt
import requests

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import (
    SaasConfigItem,
    SaasConfigEnum,
    Secret,
    ReturnCustomField
)

# Constants
TOKEN_ENDPOINT = "/services/authorization/tokens"
TOKEN_EXPIRES_ON = "+30d"
API_TIMEOUT = 30
DEFAULT_SPLUNK_PORT = 8089
CERTIFICATE_LINE_LENGTH = 64
CERTIFICATE_BEGIN_MARKER = "-----BEGIN CERTIFICATE-----"
CERTIFICATE_END_MARKER = "-----END CERTIFICATE-----"

class SaasPlugin(SaasPluginBase):
    name = "Splunk Token Rotation"
    summary = "Rotate Splunk Authentication token"
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self, user, config_record, provider_config=None, force_fail=False
    ):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self._verify_param = None
        self._cert_file = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests", "PyJWT"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="splunk_host",
                label="Splunk Host URL",
                desc=(
                    "Splunk management port URL "
                    "(e.g., https://example.com:8089)."
                ),
                type="url",
                required=True,
            ),
            SaasConfigItem(
                id="auth_token",
                label="Bearer Token",
                desc="Current Splunk bearer token used for authentication.",
                type="secret",
                is_secret=True,
                required=True,
            ),
            SaasConfigItem(
                id="verify_ssl",
                label="Verify SSL",
                desc="Whether to validate the SSL certificate.",
                type="enum",
                required=False,
                default_value="True",
                enum_values=[
                    SaasConfigEnum(
                        value="True",
                        desc="Validate SSL"
                    ),
                    SaasConfigEnum(
                        value="False",
                        desc="Allow self-signed certificates"
                    ),
                ]
            ),
            SaasConfigItem(
                id="ssl_content",
                label="SSL Certificate Content",
                desc="Optional custom CA certificate content.",
                type="multiline",
                is_secret=True,
                required=False,
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

    @staticmethod
    def fix_certificate_format(cert_content: str) -> str:
        """Fix certificate format by ensuring proper line breaks.
        Args:
            cert_content: Raw certificate content
        Returns:
            Properly formatted certificate content
        """
        cleaned = (cert_content.replace('\n', '')
                   .replace('\r', '')
                   .replace(' ', '')
                   .replace('\t', ''))

        if not (cleaned.startswith(CERTIFICATE_BEGIN_MARKER)
            and cleaned.endswith(CERTIFICATE_END_MARKER)):
            return cert_content
        start_idx = cleaned.find(CERTIFICATE_BEGIN_MARKER) + len(CERTIFICATE_BEGIN_MARKER)
        end_idx = cleaned.find(CERTIFICATE_END_MARKER)
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

    def create_ssl_verification(
        self,
        cert_content: Optional[str],
        verify_ssl: bool
    ) -> tuple[bool, Optional[str]]:
        """Create SSL context if custom certificate and SSL verification enabled.

        Args:
            cert_content: The certificate content string
            verify_ssl: Whether SSL verification is enabled

        Returns:
            Optional[ssl.SSLContext]: SSL context if custom cert provided, None otherwise

        Raises:
            SaasException: If the SSL certificate content is invalid or
            SSL verification is disabled with custom cert
        """
        if not cert_content or not cert_content.strip():
            Log.debug("No SSL certificate content provided")
            return verify_ssl, None

        # Security enhancement: Require SSL verification when custom
        # certificate is provided
        if not verify_ssl:
            Log.error(
                "Custom SSL certificate provided but SSL verification is disabled"
            )
            raise SaasException(
                (
                    "Security error: Custom SSL certificate cannot be used "
                    "with SSL verification disabled"
                ),
                code="ssl_verification_required"
            )

        try:
            # Fix certificate format if needed
            stripped_content = cert_content.strip()

            # Check if certificate contains valid headers and footers
            has_begin_marker = stripped_content.startswith(CERTIFICATE_BEGIN_MARKER)
            has_end_marker = stripped_content.endswith(CERTIFICATE_END_MARKER)

            if has_begin_marker and has_end_marker:
                Log.debug("Certificate has valid markers - normalizing format")
                stripped_content = SaasPlugin.fix_certificate_format(
                    stripped_content
                )
                Log.debug("Certificate format normalized")
            else:
                # Try to fix format for certificates without proper markers
                Log.debug("Attempting to fix certificate format")
                stripped_content = SaasPlugin.fix_certificate_format(
                    stripped_content
                )

            if not stripped_content.startswith(CERTIFICATE_BEGIN_MARKER):
                raise SaasException(
                    (
                        f"Invalid SSL certificate format: Missing "
                        f"'{CERTIFICATE_BEGIN_MARKER}' header"
                    ),
                    code="invalid_ssl_cert_format"
                )

            if not stripped_content.endswith(CERTIFICATE_END_MARKER):
                raise SaasException(
                    (
                        f"Invalid SSL certificate format: Missing "
                        f"'{CERTIFICATE_END_MARKER}' footer"
                    ),
                    code="invalid_ssl_cert_format"
                )

            Log.debug("Creating temporary certificate file for requests")

            # Create a temporary file for the certificate
            temp_cert_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.pem', delete=False
            )
            temp_cert_file.write(stripped_content)
            temp_cert_file.close()
            Log.info(
                "Custom SSL certificate validated and temporary file created successfully"
            )
            return True, temp_cert_file.name

        except SaasException:
            raise
        except ssl.SSLError as e:
            Log.error(f"Invalid SSL certificate content: {e}")
            raise SaasException(
                f"Invalid SSL certificate: {e}",
                code="invalid_ssl_cert"
            ) from e
        except (ValueError, TypeError, AttributeError) as e:
            Log.error(f"Unexpected error processing SSL certificate: {e}")
            raise SaasException(
                f"Failed to process SSL certificate: {e}",
                code="ssl_cert_processing_error"
            ) from e

    def _get_field_value_from_fields(self, field_name: str) -> Optional[str]:
        """Extract field value from user fields.

        Args:
            field_name: The label of the field to extract

        Returns:
            The field value as a string, or None if not found
        """
        for field in self.user.fields:
            if field.label == field_name:
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    return value[0].strip() if value else None
                return value.strip() if value else None
        return None

    def _cleanup_temp_files(self) -> None:
        """Clean up temporary certificate files."""
        if self._cert_file and os.path.exists(self._cert_file):
            try:
                os.unlink(self._cert_file)
                Log.debug("Cleaned up temporary certificate file")
            except OSError as e:
                Log.warning(f"Failed to clean up temporary file {self._cert_file}: {e}")
            finally:
                self._cert_file = None

    def _get_url(self, path: str) -> str:
        base = self.get_config("splunk_host").rstrip("/")
        return f"{base}{path}"

    def _make_http_request(
        self,
        method: str,
        url: str,
        headers: dict,
        data: dict = None,
        timeout: int = API_TIMEOUT
    ) -> requests.Response:
        """Make HTTP request with SSL verification.

        Args:
            method: HTTP method (GET, POST, DELETE)
            url: Request URL
            headers: Request headers
            data: Request data (optional)
            timeout: Request timeout in seconds

        Returns:
            requests.Response: HTTP response object

        Raises:
            requests.RequestException: If request fails
        """
        request_kwargs = {
            "url": url,
            "headers": headers,
            "verify": self._verify_param,
            "timeout": timeout,
            "params": {"output_mode": "json"}
        }

        if data is not None:
            request_kwargs["data"] = data

        valid_methods = {"GET", "POST", "DELETE"}
        method_upper = method.upper()
        if method_upper not in valid_methods:
            raise ValueError(f"Unsupported HTTP method: {method_upper}")
        
        return requests.request(method=method_upper, **request_kwargs)

    def _get_auth_headers(self, content_type: str = None) -> dict:
        """Get authorization headers for API requests.

        Args:
            content_type: Optional content type header

        Returns:
            dict: Headers dictionary with authorization
        """
        headers = {
            "Authorization": f"Bearer {self.get_config('auth_token')}"
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _decode_jwt_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            Log.debug("Sucessfully decoded jwt token")
            return payload
        except jwt.DecodeError as e:
            raise SaasException(f"Failed to decode JWT token: {e}") from e

    def handle_http_error_response(self, response: requests.Response, action: str = "processing request"):
        """
        Handles non-success HTTP responses by logging and raising appropriate SaasExceptions.

        Args:
            response (requests.Response): The HTTP response object.
            action (str): A short description of the action being performed, used in logs.

        Raises:
            SaasException: Custom exception based on status code.
        """
        status = response.status_code
        message = response.json()

        Log.error(f"HTTP {status} during {action}: {message}")

        if status == 400:
            raise SaasException(f"Bad Request while {action}.", code="bad_request")
        elif status == 401:
            raise SaasException(f"Unauthorized access while {action}.", code="unauthorized")
        elif status == 403:
            raise SaasException(f"Forbidden: Access denied while {action}.", code="forbidden")
        elif status == 404:
            raise SaasException(f"Resource not found while {action}.", code="not_found")
        elif status == 500:
            raise SaasException(f"Server error while {action}.", code="server_error")
        else:
            raise SaasException(f"Unhandled HTTP error ({status}) while {action}.", code="http_error")


    def _generate_token(self, audience: str, name: str) -> str:
        """Generate a new Splunk authentication token.

        Args:
            audience: Token audience
            name: Token name

        Returns:
            str: The generated token

        Raises:
            SaasException: If token generation fails
        """
        url = self._get_url(f"{TOKEN_ENDPOINT}")
        headers = self._get_auth_headers("application/x-www-form-urlencoded")
        data = {
            "name": name,
            "audience": audience,
            "expires_on": TOKEN_EXPIRES_ON
        }
        try:
            response = self._make_http_request("POST", url, headers, data)
            if response.status_code == 201:
                try:
                    json_data = response.json()
                    new_token = json_data["entry"][0]["content"]["token"]
                except (KeyError, ValueError, IndexError) as e:
                    raise SaasException(f"Failed to parse token response: {e}") from e
                Log.info("New token generated successfully.")
                return new_token
            else:
                self.handle_http_error_response(response, action="generating token")
        except (requests.RequestException, KeyError, ValueError) as e:
            raise SaasException(f"Failed to generate new token: {e}") from e

    def _delete_token(self, token_id: str, token_name: str) -> None:
        """Delete a token by ID and name.

        Args:
            token_id: The token ID to delete
            token_name: The token name to delete
        """
        url = self._get_url(f"{TOKEN_ENDPOINT}/{token_name}")
        headers = self._get_auth_headers("application/x-www-form-urlencoded")
        data = {"id": token_id}
        try:
            response = self._make_http_request("DELETE", url, headers, data)
            if response.status_code == 200:
                Log.info("Old token deleted successfully.")
            else:
                self.handle_http_error_response(response=response, action="deleting token")
        except requests.RequestException as e:
            Log.warning(f"Error deleting old token: {e}")

    def _check_token_exists(self, token_id: str) -> bool:
        """Check if a token exists in Splunk.

        Args:
            token_id: The token ID to check

        Returns:
            bool: True if token exists, False otherwise
        """
        url = self._get_url(f"{TOKEN_ENDPOINT}/{token_id}")
        headers = self._get_auth_headers()
        try:
            response = self._make_http_request("GET", url, headers)
            if response.status_code == 200:
                Log.debug(
                    "Old Token exists in splunk"
                )
                return True
            else:
                self.handle_http_error_response(response, "fetching old token details")
        except requests.RequestException as e:
            Log.warning(f"Error checking token existence: {e}")
            return False

    def change_password(self):
        """
        Instead of changing a password, we rotate the Splunk token.
        This is the entry point method called during rotation.
        """
        Log.info("Starting Splunk token rotation")

        # Setup SSL verification once for all HTTP requests
        verify_ssl = self.should_verify_ssl(self.get_config("verify_ssl"))
        self._verify_param, self._cert_file = self.create_ssl_verification(
            cert_content=self.get_config("ssl_content"), verify_ssl=verify_ssl
        )
        if self._cert_file:
            self._verify_param = self._cert_file

        old_rotation_token = self._get_field_value_from_fields("auth_token")
        if not old_rotation_token:
            raise SaasException(
                "No bearer token provided for authentication."
            )

        payload = self._decode_jwt_token(old_rotation_token)
        old_rotation_token_id = payload.get("jti")
        audience = payload.get("aud")
        token_user = str(payload.get("sub"))

        if not old_rotation_token_id or not audience:
            raise SaasException(
                "JWT is missing required claims: 'jti' or 'aud'."
            )

        if self._check_token_exists(old_rotation_token_id):
            Log.info("Old token ID is present in Splunk.")

        new_token = self._generate_token(audience, token_user)

        self._delete_token(old_rotation_token_id, token_user)
        self.add_return_field(
            ReturnCustomField(
                label="auth_token",
                type="secret",
                value=Secret(new_token)
            )
        )

        Log.info("Splunk token rotation completed successfully.")

        self._cleanup_temp_files()

    def rollback_password(self):
        """
        Rollback is not supported
        """
        Log.info("Rollback is not supported")

    def add_return_field(self, field: ReturnCustomField):
        """Add return field to the list of fields to return.

        Args:
            field: The custom field to add to return fields
        """
        self.return_fields.append(field)