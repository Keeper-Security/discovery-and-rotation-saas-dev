from __future__ import annotations

import base64
from typing import Dict, List, Optional, Any, TYPE_CHECKING

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    AuthorizationException,
    BadRequestError,
    ConflictError,
    NotFoundError
)

from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import SaasConfigItem, ReturnCustomField, SaasConfigEnum
from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.secret import Secret
try:
    from ..common.utils import (
        validate_elasticsearch_url,
        should_verify_ssl,
        build_elasticsearch_client_config
    )
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from common.utils import (
        validate_elasticsearch_url,
        should_verify_ssl,
        build_elasticsearch_client_config
    )

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

# Constants
API_TIMEOUT = 30
MAX_RETRIES = 3
PRIVILEGES_TO_PRESERVE = ["cluster", "indices", "applications", "run_as"]
TOKEN_EXPIRATION_IN_DAYS = "30d"


class SaasPlugin(SaasPluginBase):
    """Elasticsearch API Key rotation plugin."""

    name = "Elasticsearch API Key"
    summary = "Rotate API keys in Elasticsearch for authentication."
    readme = "README_elasticsearch_api_key.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self, user, config_record, provider_config=None, force_fail=False):
        """Initialize the plugin."""
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None
        self._current_api_key_info = None

    @classmethod
    def requirements(cls) -> List[str]:
        """Return required Python packages."""
        return ["elasticsearch"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        """Define configuration schema for the plugin."""
        return [
            SaasConfigItem(
                id="elasticsearch_url",
                label="Elasticsearch URL",
                desc="The URL to the Elasticsearch cluster. Example: https://elasticsearch.example.com:9200",
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="username",
                label="Admin Username",
                desc="Elasticsearch admin username for basic authentication.",
                required=True
            ),
            SaasConfigItem(
                id="password",
                label="Admin Password",
                desc="Elasticsearch admin password for basic authentication.",
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
                default_value="False",
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
                    "CA certificate content (.crt format). "
                    "Only required when 'Verify SSL' is set to 'True'."
                ),
                type="multiline",
                is_secret=True,
                required=False
            )
        ]

    @property
    def can_rollback(self) -> bool:
        """Check if rollback is possible."""
        return self._current_api_key_info is not None

    @property
    def verify_ssl(self) -> bool:
        """Get SSL verification setting."""
        return should_verify_ssl(self.get_config("verify_ssl"))

    def _get_api_key_from_user_fields(self) -> str:
        """Extract encoded API key from user fields."""
        for field in self.user.fields:
            if field.label == "api_key_encoded":
                value = field.values[0] if field.values else None
                if isinstance(value, list):
                    return value[0] if value else None
                return value

        raise SaasException(
            "Encoded API key is required in user fields",
            code="api_key_required"
        )

    def _extract_api_key_id(self, encoded_api_key: str) -> str:
        """Extract API key ID from encoded format."""
        try:
            decoded = base64.b64decode(encoded_api_key).decode('utf-8')
            if ':' not in decoded:
                raise ValueError("No colon separator found in decoded API key")
            return decoded.split(':')[0]
        except Exception as e:
            raise SaasException(
                "Invalid API key format. Expected base64 encoded 'id:api_key'",
                code="invalid_api_key_format"
            ) from e

    def _initialize_elasticsearch_client(self) -> Elasticsearch:
        """Initialize and return Elasticsearch client."""
        elasticsearch_url = self.get_config("elasticsearch_url")
        validate_elasticsearch_url(elasticsearch_url)
        username = self.get_config("username")
        password = self.get_config("password")
        cert_content = self.get_config("ssl_content")

        Log.debug("Initializing Elasticsearch client with basic authentication")

        try:
            client_config = build_elasticsearch_client_config(
                hosts=[elasticsearch_url],
                verify_ssl=self.verify_ssl,
                cert_content=cert_content,
                basic_auth=(username, password),
                request_timeout=API_TIMEOUT,
                max_retries=MAX_RETRIES
            )

            client = Elasticsearch(**client_config)
            client.ping()
            Log.debug("Successfully connected to Elasticsearch")
            return client

        except AuthenticationException as e:
            raise SaasException(
                "Authentication failed. Verify admin credentials are correct",
                code="authentication_failed"
            ) from e
        except Exception as e:
            Log.error(f"Failed to connect to Elasticsearch: {e}")
            raise SaasException(
                f"Failed to connect to Elasticsearch: {e}",
                code="elasticsearch_connection_error"
            ) from e

    @property
    def client(self) -> Elasticsearch:
        """Get or create Elasticsearch client."""
        if self._client is None:
            self._client = self._initialize_elasticsearch_client()
        return self._client

    def _fetch_api_key_info(self, api_key_id: str) -> Dict[str, Any]:
        """Fetch information about an existing API key."""
        try:
            Log.info(f"Getting API key information for ID: {api_key_id}")
            response = self.client.security.get_api_key(id=api_key_id)
            
            if not response.get("api_keys"):
                raise SaasException(
                    f"API key '{api_key_id}' not found",
                    code="api_key_not_found"
                )
            
            api_key_info = response["api_keys"][0]
            Log.info("Successfully retrieved API key information")
            return api_key_info

        except AuthenticationException as e:
            raise SaasException(
                "Authentication failed when getting API key info",
                code="authentication_failed"
            ) from e
        except AuthorizationException as e:
            raise SaasException(
                "Authorization failed while retrieving API key information. "
                "Please ensure the user has one of the ['read_security', 'manage_api_key'] "
                "permission assigned in their role.",
                code="authorization_failed"
            ) from e
        except NotFoundError as e:
            raise SaasException(
                f"API key '{api_key_id}' not found",
                code="api_key_not_found"
            ) from e
        except Exception as e:
            error_msg = str(e)
            Log.error(f"Elasticsearch error getting API key info: {error_msg}")
            raise SaasException(
                f"Failed to get API key information: {error_msg}",
                code="elasticsearch_error"
            ) from e

    def _clean_role_descriptors(self, role_descriptors: Optional[Dict]) -> Optional[Dict]:
        """Clean and validate role descriptors for API key creation."""
        if not role_descriptors:
            Log.debug("No role descriptors to clean")
            return None

        try:
            cleaned_descriptors = {}

            for role_name, role_def in role_descriptors.items():
                if not isinstance(role_def, dict):
                    Log.warning(f"Skipping invalid role '{role_name}': not a dictionary")
                    continue

                cleaned_role = self._extract_valid_privileges(role_def)

                if cleaned_role:
                    cleaned_descriptors[role_name] = cleaned_role
                else:
                    Log.warning(f"Role '{role_name}' has no valid privileges, skipping")

            if cleaned_descriptors:
                Log.debug(f"Cleaned role descriptors: {list(cleaned_descriptors.keys())}")
                return cleaned_descriptors
            else:
                Log.warning("No valid role descriptors found after cleaning")
                return None

        except Exception as e:
            Log.error(f"Error validating role descriptors: {e}")
            return None

    def _extract_valid_privileges(self, role_def: Dict) -> Dict:
        """Extract valid privileges from a role definition."""
        cleaned_role = {}

        # Standard privilege types allowed during API key creation
        privilege_types = PRIVILEGES_TO_PRESERVE

        for privilege_type in privilege_types:
            if privilege_type in role_def and role_def[privilege_type]:
                cleaned_role[privilege_type] = role_def[privilege_type]

        return cleaned_role

    def _create_new_api_key(self, name: str, role_descriptors: Optional[Dict] = None,
                           expiration: Optional[str] = None) -> Dict[str, Any]:
        """Create a new API key with specified parameters."""
        Log.info(f"Creating API key '{name}'")
        
        cleaned_role_descriptors = self._clean_role_descriptors(role_descriptors)
        request_body = self._build_api_key_request(name, cleaned_role_descriptors, expiration)
        
        try:
            response = self.client.security.create_api_key(**request_body)
            Log.info(f"Successfully created API key '{name}'")
            return response

        except AuthenticationException as e:
            Log.error(f"Authentication failed when creating API key: {e}")
            raise SaasException(
                "Authentication failed when creating API key",
                code="authentication_failed"
            ) from e
        except AuthorizationException as e:
            Log.error(f"Authorization failed when creating API key: {e}")
            raise SaasException(
                "Authorization failed when creating API key, "
                "make sure the user have the 'manage_own_api_key' permission in the role",
                code="authorization_failed"
            ) from e
        except BadRequestError as e:
            Log.error(f"Bad request when creating API key: {e}")
            error_msg = str(e)
            Log.error(f"Request body that failed: {request_body}")
            raise SaasException(
                f"Invalid request parameters: {error_msg}",
                code="bad_request"
            ) from e
        except ConflictError as e:
            Log.error(f"API key '{name}' already exists: {e}")
            raise SaasException(
                f"API key '{name}' already exists",
                code="api_key_already_exists"
            ) from e
        except Exception as e:
            Log.error(f"Unexpected error creating API key: {e}")
            error_msg = str(e)
            Log.error(f"Elasticsearch error creating API key: {error_msg}")
            raise SaasException(
                f"Failed to create API key: {error_msg}",
                code="elasticsearch_error"
            ) from e

    def _build_api_key_request(self, name: str, role_descriptors: Optional[Dict],
                              expiration: Optional[str]) -> Dict[str, Any]:
        """Build the request body for API key creation."""
        request_body = {"name": name}
        
        if role_descriptors:
            request_body["role_descriptors"] = role_descriptors
        else:
            Log.debug("No role descriptors provided - using default permissions")
        
        if expiration:
            request_body["expiration"] = expiration
        
        return request_body

    def _invalidate_api_key(self, api_key_id: str) -> None:
        """Invalidate an existing API key."""
        Log.info(f"Invalidating API key with ID: {api_key_id}")
        try:
            self.client.security.invalidate_api_key(ids=[api_key_id])
            Log.info("Successfully invalidated API key")
        except NotFoundError:
            Log.warning(f"API key {api_key_id} not found (may already be invalid)")
        except AuthenticationException as e:
            raise SaasException(
                "Authentication failed when invalidating API key",
                code="authentication_failed"
            ) from e
        except Exception as e:
            error_msg = str(e)
            Log.error(f"Elasticsearch error invalidating API key: {error_msg}")
            raise SaasException(
                f"Failed to invalidate API key: {error_msg}",
                code="elasticsearch_error"
            ) from e

    def _add_return_fields(self, api_key_response: Dict[str, Any]) -> None:
        """Add return fields to be stored in PAM."""
        name = api_key_response.get("name")
        encoded = api_key_response.get("encoded")

        if name:
            self.add_return_field(
                ReturnCustomField(
                    label="API Key Name",
                    value=Secret(name)
                )
            )

        if encoded:
            self.add_return_field(
                ReturnCustomField(
                    label="api_key_encoded",
                    type="secret",
                    value=Secret(encoded)
                )
            )


    def change_password(self):
        """Rotate the API key by creating a new one and invalidating the old one."""
        Log.info("Starting Elasticsearch API key rotation")
        if self.client:
            pass
        else:
            Log.error("Failed to connect to Elasticsearch")
            raise SaasException(
                "Failed to connect to Elasticsearch",
                code="elasticsearch_connection_error"
            )

        try:
            current_encoded_api_key = self._get_api_key_from_user_fields()
            api_key_id = self._extract_api_key_id(current_encoded_api_key)

            self._current_api_key_info = self._fetch_api_key_info(api_key_id)
            current_name = self._current_api_key_info.get("name", "rotated-api-key")
            role_descriptors = self._current_api_key_info.get("role_descriptors")

            new_api_key_response = self._create_new_api_key(
                name=current_name,
                role_descriptors=role_descriptors,
                expiration=TOKEN_EXPIRATION_IN_DAYS
            )

            self._add_return_fields(new_api_key_response)

            self._invalidate_api_key(api_key_id)

            Log.info("Successfully rotated Elasticsearch API key")

        except SaasException:
            raise
        except Exception as e:
            Log.error(f"Unexpected error rotating API key: {e}")
            raise SaasException(
                f"Unexpected error: {e}",
                code="unexpected_error"
            ) from e

    def rollback_password(self):
        """Rollback is not supported for API key rotation."""
        Log.warning("Rollback not supported for API key rotation")
        raise SaasException(
            "Rollback not supported for API key rotation. "
            "The old API key has been invalidated.",
            code="rollback_not_supported"
        )