from __future__ import annotations

import atexit
import os
import ssl
import tempfile
from typing import List, Optional, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import SaasConfigItem, Secret, SaasConfigEnum

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

API_TIMEOUT = 30
API_ENDPOINT = "/access/api/v2"
HEALTH_ENDPOINT = "/access/api/v1/system/ping"

class SaasPlugin(SaasPluginBase):
    name = "JFrog User Password Rotation"
    summary = "Change a user password in JFrog platform."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self,
        user: SaasUser,
        config_record: Record,
        provider_config=None,
        force_fail=False
    ):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self._session = None
        self._can_rollback = False
        self._temp_cert_file: Optional[str] = None


    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="jfrog_url",
                label="JFrog URL",
                desc=(
                    "The base URL of your JFrog platform "
                    "(e.g., https://mycompany.jfrog.io)."
                ),
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="access_token",
                label="Admin Access Token",
                desc="JFrog admin access token for authentication.",
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
                    "CA certificate content (.crt format). "
                    "Only required when 'Verify SSL' is set to 'True' "
                    "and using custom certificates."
                ),
                type="multiline",
                is_secret=True,
                required=False
            )
        ]

    def __del__(self):
        self._cleanup_temp_files()

    @property
    def can_rollback(self) -> bool:
        return self._can_rollback

    @can_rollback.setter
    def can_rollback(self, value: bool):
        self._can_rollback = value

    @staticmethod
    def validate_jfrog_url(url: str) -> None:
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL structure")
            if parsed.scheme not in ("http", "https"):
                raise ValueError("URL must use http or https")
        except Exception as e:
            raise SaasException(
                "Invalid JFrog platform URL. Must be a valid http/https URL.",
                code="invalid_url"
            ) from e

    @staticmethod
    def should_verify_ssl(verify_ssl_config_value: str) -> bool:
        return str(verify_ssl_config_value) == "True"

    def _cleanup_temp_files(self) -> None:
        if self._temp_cert_file and os.path.exists(self._temp_cert_file):
            try:
                os.unlink(self._temp_cert_file)
                Log.debug(f"Cleaned up temporary certificate file: {self._temp_cert_file}")
            except OSError as e:
                Log.warning(f"Failed to clean up temporary certificate file {self._temp_cert_file}: {e}")
            finally:
                self._temp_cert_file = None

    def _create_temp_cert_file(self, cert_content: str) -> str:
        try:
            self._cleanup_temp_files()
            
            temp_fd, temp_path = tempfile.mkstemp(suffix='.crt', prefix='jfrog_cert_')
            try:
                with os.fdopen(temp_fd, 'w') as temp_file:
                    temp_file.write(cert_content.strip())
                    temp_file.flush()
                
                self._temp_cert_file = temp_path
                
                atexit.register(self._cleanup_temp_files)
                
                Log.debug(f"Created temporary certificate file: {temp_path}")
                return temp_path
                
            except Exception:
                try:
                    os.close(temp_fd)
                    os.unlink(temp_path)
                except OSError:
                    pass
                raise
                
        except Exception as e:
            Log.error(f"Failed to create temporary certificate file: {e}")
            raise SaasException(f"Unable to create temporary certificate file: {e}") from e

    @staticmethod
    def create_ssl_context(
        cert_content: Optional[str], 
        verify_ssl: bool
    ) -> Optional[ssl.SSLContext]:
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

    @property
    def jfrog_url(self) -> str:
        url = self.get_config("jfrog_url")
        if not url:
            raise SaasException("JFrog platform URL is required.")
        
        self.validate_jfrog_url(url)
        return url.rstrip('/')


    @property
    def admin_access_token(self) -> Secret:
        token = self.get_config("access_token")
        if not token:
            raise SaasException("Admin access token is required.")
        return Secret(token)

    @property
    def verify_ssl(self) -> bool:
        verify = self.get_config("verify_ssl", "False")
        return self.should_verify_ssl(verify)

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            
            verify_ssl = self.verify_ssl
            cert_content = self.get_config("ssl_content")
            
            if verify_ssl:
                if cert_content and cert_content.strip():
                    ssl_context = self.create_ssl_context(cert_content, verify_ssl)
                    if ssl_context:
                        cert_file_path = self._create_temp_cert_file(cert_content)
                        self._session.verify = cert_file_path
                        Log.debug(f"Using custom SSL certificate file: {cert_file_path}")
                    else:
                        Log.warning("Invalid certificate content, falling back to standard SSL verification")
                        self._session.verify = True
                else:
                    self._session.verify = True
                    Log.debug("Using standard SSL verification")
            else:
                self._session.verify = False
                Log.debug("SSL verification disabled")
            
            self._session.timeout = API_TIMEOUT
            
            self._session.headers.update({
                'Authorization': f'Bearer {self.admin_access_token.value}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        return self._session

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = urljoin(self.jfrog_url + "/", endpoint.lstrip('/'))
        
        try:
            response = self.session.request(method, url, **kwargs)            
            return response
            
        except Timeout as err:
            Log.error(f"Request timeout to JFrog API: {err}")
            raise SaasException("Request timeout to JFrog platform") from err
        except ConnectionError as err:
            Log.error(f"Connection error to JFrog API: {err}")
            raise SaasException("Cannot connect to JFrog platform") from err
        except RequestException as err:
            Log.error(f"Request error to JFrog API: {err}")
            raise SaasException(f"JFrog API request failed: {err}") from err

    def _test_connection(self) -> None:
        try:
            response = self._make_request('GET', HEALTH_ENDPOINT)
            if response.status_code != 200:
                Log.error(f"JFrog platform health check failed with status {response.status_code}")
                raise SaasException("Cannot connect to JFrog platform")
            Log.info("JFrog platform connection test successful")
        except SaasException:
            # Re-raise SaasExceptions (like timeout errors) as-is to preserve their specific messages
            raise
        except Exception as err:
            Log.error(f"JFrog platform connection test failed: {err}")
            raise SaasException("Cannot connect to JFrog platform") from err

    def _verify_user_exists(self):
        username = self.user.username.value
        
        try:
            response = self._make_request('GET', f'{API_ENDPOINT}/users/{username}')
            
            if response.status_code == 200:
                Log.debug(f"User {username} found in JFrog platform")
                self.can_rollback = True
            elif response.status_code == 404:
                Log.error(f"User {username} not found in JFrog platform")
                raise SaasException(f"User '{username}' does not exist in JFrog platform")
            elif response.status_code == 401:
                Log.error("Authentication failed when verifying user")
                raise SaasException("Authentication failed - invalid admin credentials")
            elif response.status_code == 403:
                Log.error("Authorization failed when verifying user")
                raise SaasException("Authorization failed - insufficient permissions")
            else:
                error_msg = f"Failed to verify user existence: HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg += f" - {error_data['error']}"
                except:
                    error_msg += f" - {response.text}"
                
                Log.error(error_msg)
                raise SaasException(error_msg)
                
        except SaasException:
            raise
        except Exception as err:
            Log.error(f"Error verifying user existence: {err}")
            raise SaasException(f"Failed to verify user existence: {err}") from err

    def _change_user_password(self, password: Secret):
        username = self.user.username.value

        Log.info(f"Changing password for JFrog user: {username}")
        
        try:
            self._verify_user_exists()
            
            payload = {
                "password": password.value
            }
            
            response = self._make_request(
                'PUT',
                f'{API_ENDPOINT}/users/{username}/password',
                json=payload
            )
            
            if response.status_code == 204:
                Log.info(f"Password changed successfully for user: {username}")
            elif response.status_code == 401:
                raise SaasException("Authentication failed - invalid admin credentials")
            elif response.status_code == 403:
                raise SaasException("Authorization failed - insufficient permissions")
            elif response.status_code == 404:
                raise SaasException(f"User '{username}' not found")
            elif response.status_code == 400:
                error_msg = "Invalid password change request"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg += f" - {error_data['error']}"
                    elif 'message' in error_data:
                        error_msg += f" - {error_data['message']}"
                except:
                    error_msg += f" - {response.text}"
                
                self._can_rollback = True
                raise SaasException(error_msg)
            else:
                error_msg = f"Failed to change password: HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg += f" - {error_data['error']}"
                except:
                    error_msg += f" - {response.text}"
                
                self._can_rollback = True
                raise SaasException(error_msg)
        except Exception as err:
            self._can_rollback = True
            Log.error(f"Unexpected error changing password: {err}")
            raise SaasException(f"Failed to change password: {err}") from err

    def change_password(self):
        if self.user.new_password is None:
            raise SaasException(
                "No new password provided."
            )

        self._test_connection()

        Log.info("Starting password change for JFrog user")

        self._change_user_password(self.user.new_password)
        Log.debug(
            f"Password change completed successfully for user "
            f"{self.user.username.value}"
        )

    def rollback_password(self):
        if self.user.prior_password is None:
            raise SaasException(
                "Cannot rollback password. No prior password available."
            )

        Log.info("Rolling back password change for JFrog user")
        if self.user.prior_password is not None:
            self._change_user_password(self.user.prior_password)
        Log.debug(
            f"Password rollback completed successfully for user "
            f"{self.user.username.value}"
        )