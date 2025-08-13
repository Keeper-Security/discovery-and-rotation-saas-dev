from __future__ import annotations

import atexit
import base64
import json
import os
import re
import ssl
import tempfile
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, SaasConfigItem, Secret, SaasConfigEnum

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

API_TIMEOUT = 30
EXPIRES_IN = 2592000 # 30 days
TOKEN_ENDPOINT = '/access/api/v1/tokens'
HEALTH_ENDPOINT = '/access/api/v1/system/ping'

class SaasPlugin(SaasPluginBase):
    name = "JFrog Access Token"
    summary = "Rotate JFrog access tokens for platform authentication."
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
        self._session = None
        self._temp_cert_file: Optional[str] = None
        self._old_token = None

    def __del__(self):
        self._cleanup_temp_files()

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
                desc="JFrog admin access token to be rotated.",
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

    @classmethod
    def requirements(cls) -> List[str]:
        return ["requests"]

    @property
    def can_rollback(self) -> bool:
        return False

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

    @staticmethod
    def _decode_jwt_payload(token: str) -> Dict[str, Any]:
        try:
            # Handle test tokens with prefix (for testing only)
            if token.startswith("fake_test_token_"):
                token = token[16:]  # Remove "fake_test_token_" prefix
            
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            payload_part = parts[1]
            
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            
            decoded_bytes = base64.urlsafe_b64decode(payload_part)
            payload = json.loads(decoded_bytes.decode('utf-8'))
            
            return payload
            
        except (ValueError, json.JSONDecodeError, Exception) as e:
            Log.error(f"Failed to decode JWT token: {e}")
            raise SaasException(f"Invalid JWT token format: {e}") from e

    def _cleanup_temp_files(self) -> None:
        if self._temp_cert_file and os.path.exists(self._temp_cert_file):
            try:
                os.unlink(self._temp_cert_file)
                Log.debug("Cleaned up temporary certificate file")
            except OSError as e:
                Log.warning(f"Failed to clean up temporary certificate file: {e}")
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
                
                Log.debug(f"Created temporary certificate file")
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

    def _validate_username(self, username: str) -> None:
        if not username:
            raise SaasException("Username cannot be empty.")
        
        if len(username) < 1 or len(username) > 128:
            raise SaasException("Username must be between 1 and 128 characters.")

    @property
    def jfrog_url(self) -> str:
        url = self.get_config("jfrog_url")
        if url is None:
            raise SaasException(
                "The JFrog platform URL is required for token rotation."
            )
        
        self.validate_jfrog_url(url)
        return url.rstrip('/')

    @property
    def current_access_token(self) -> Optional[str]:
        for field in self.user.fields:
            if field.label == "access_token":
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    return value[0] if value else None
                return value
        raise SaasException(
            "Access token is required in user record",
            code="access_token"
        )

    @property
    def get_token_description(self) -> Optional[str]:
        for field in self.user.fields:
            if field.label == "token_description":
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    return value[0] if value else None
                return value
        raise SaasException(
            "Token description is required in user record",
            code="token_description"
        )

    @property
    def current_access_token_scope(self) -> Optional[str]:
        for field in self.user.fields:
            if field.label == "jfrog_token_scope":
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    return value[0]
                return value
        return None

    @property
    def username(self) -> str:
        token = self.current_access_token
        if token is None:
            raise SaasException("Current access token is required to extract username")
        
        try:
            payload = self._decode_jwt_payload(token)
            sub = payload.get('sub', '')
            
            if '/users/' in sub:
                username = sub.split('/users/')[-1]
                self._validate_username(username)
                return username
            else:
                raise SaasException(f"Invalid subject format in token: {sub}")
                
        except Exception as e:
            raise SaasException(f"Cannot extract username from access token: {e}") from e

    @property
    def token_scope(self) -> str:
        scope = self.current_access_token_scope
        if scope is not None:
            return scope
        
        token = self.current_access_token
        if token is not None:
            try:
                payload = self._decode_jwt_payload(token)
                scp = payload.get('scp', '')
                if scp:
                    return scp
            except Exception as e:
                Log.warning(f"Failed to extract scope from token, using config: {e}")
        
        scope = self.get_config("token_scope", "applied-permissions/user")
        return scope

    @property
    def verify_ssl(self) -> bool:
        verify = self.get_config("verify_ssl", "False")
        return self.should_verify_ssl(verify)

    @property
    def admin_access_token(self) -> Secret:
        token = self.get_config("access_token")
        if not token:
            raise SaasException("Admin access token is required.")
        return Secret(token)

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
                        Log.debug(f"Using custom SSL certificate file")
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
                raise SaasException(f"JFrog platform connection test failed: {response.status_code}")
            Log.info("JFrog platform connection test successful")
        except Exception as err:
            Log.error(f"JFrog platform connection test failed: {err}")
            raise SaasException("Cannot connect to JFrog platform") from err

    def _verify_token_works(self, token: str) -> bool:
        try:
            with requests.Session() as test_session:
                test_session.verify = self.session.verify
                test_session.headers.update({
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
            })
                
            url = urljoin(self.jfrog_url + "/", HEALTH_ENDPOINT)
            response = test_session.get(url)
            
            if response.status_code == 200:
                Log.info("New token verification successful")
                return True
            else:
                Log.error(f"New token verification failed: {response.status_code}")
                return False
        
        except requests.exceptions.RequestException as e:
            Log.error(f"Token verification failed: {e}")
            raise SaasException(f"Token verification failed: {e}") from e
        except Exception as e:
            Log.error(f"Unexpected error during token verification: {e}")
            raise SaasException(f"Unexpected error during token verification: {e}") from e

    def _create_access_token(self) -> Dict[str, Any]:
        payload = {
            "username": self.username,
            "description": self.get_token_description,
            "scope": self.token_scope,
            "expires_in": EXPIRES_IN
        }
        
        Log.debug(f"Creating access token with scope: {self.token_scope}")
        
        response = self._make_request(
            'POST', 
            TOKEN_ENDPOINT,
            json=payload
        )
        
        if response.status_code == 200:
            token_data = response.json()
            Log.info("Successfully created new access token")
            return token_data
        elif response.status_code == 401:
            raise SaasException("Authentication failed - invalid username or password")
        elif response.status_code == 403:
            raise SaasException("Access denied - insufficient permissions to create tokens")
        else:
            error_msg = f"Failed to create access token: HTTP {response.status_code}"
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg += f" - {error_data['error']}"
            except:
                error_msg += f" - {response.text}"
            
            Log.error(error_msg)
            raise SaasException(error_msg)

    def _revoke_access_token(self, token: str) -> None:
        if not token:
            Log.warning("No token provided for revocation")
            return
        
        payload = {"token": token}
        
        Log.debug("Revoking old access token")
        
        response = self._make_request(
            'DELETE',
            f'{TOKEN_ENDPOINT}/revoke',
            json=payload
        )
        
        if response.status_code == 200:
            Log.info("Successfully revoked old access token")
        elif response.status_code == 404:
            Log.warning("Token not found for revocation (may have already expired)")
        elif response.status_code == 401:
            raise SaasException("Authentication failed while revoking token")
        elif response.status_code == 403:
            raise SaasException("Access denied - insufficient permissions to revoke tokens")
        else:
            error_msg = f"Failed to revoke access token: HTTP {response.status_code}"
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg += f" - {error_data['error']}"
            except:
                error_msg += f" - {response.text}"         
            
            raise SaasException(error_msg)

    def add_return_field(self, field: ReturnCustomField):
        self.return_fields.append(field)

    def change_password(self):
        username = self.username
        Log.info(f"Starting JFrog access token rotation for user: {username}")
        
        self._test_connection()
        self._old_token = self.current_access_token
        token_data = self._create_access_token()
        
        new_token = token_data.get('access_token')
        if not new_token:
            raise SaasException("No access token returned from JFrog API")
        
        Log.info("Verifying new access token functionality")
        if not self._verify_token_works(new_token):
            raise SaasException("New access token verification failed")
        
        Log.info(f"Successfully created and verified new access token for user {username}")
        
        try:
            self._revoke_access_token(self._old_token)
        except Exception as err:
            Log.warning(f"Failed to revoke current token: {err}")
        
        self.add_return_field(
            ReturnCustomField(
                label="access_token",
                type="secret",
                value=Secret(new_token)
            )
        )
        
        if 'token_id' in token_data:
            self.add_return_field(
                ReturnCustomField(
                    label="jfrog_token_id",
                    value=Secret(token_data['token_id'])
                )
            )
        
        if 'scope' in token_data:
            self.add_return_field(
                ReturnCustomField(
                    label="jfrog_token_scope",
                    value=Secret(token_data['scope'])
                )
            )
        
        Log.info("JFrog access token rotation completed successfully")

    def rollback_password(self):
        """
        This function is not supported for this plugin.
        """
        Log.info("Rollback is not supported")