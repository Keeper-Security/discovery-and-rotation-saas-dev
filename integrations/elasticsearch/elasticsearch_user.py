from __future__ import annotations

import ssl
from typing import List, TYPE_CHECKING

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConnectionError as ESConnectionError,
    NotFoundError,
    RequestError
)

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem, SaasConfigEnum
from urllib.parse import urlparse

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record

API_TIMEOUT = 30

class SaasPlugin(SaasPluginBase):
    """Elasticsearch User Password Rotation Plugin."""

    name = "Elasticsearch User"
    summary = "Change a user password in Elasticsearch."
    readme = "README_elasticsearch_user.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(
        self,
        user: SaasUser,
        config_record: Record,
        provider_config=None,
        force_fail=False
    ):
        """Initialize the Elasticsearch plugin."""
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self._client = None
        self._can_rollback = False

    @classmethod
    def requirements(cls) -> List[str]:
        """Return the Python package requirements for this plugin."""
        return ["elasticsearch"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        """Return the configuration schema for the plugin."""
        return [
             SaasConfigItem(
                id="elasticsearch_url",
                label="Elasticsearch URL",
                desc=(
                    "The URL to the Elasticsearch server "
                    "(e.g., https://elasticsearch.example.com:9200)."
                ),
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="api_key",
                label="API Key",
                desc="API Key for the Elasticsearch admin user.",
                type="secret",
                is_secret=True,
                required=False
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
    def verify_ssl(self) -> bool:
        """Verify SSL for the Elasticsearch client."""
        verify_ssl_value = self.get_config("verify_ssl")
        return str(verify_ssl_value) == "True"

    def _validate_url(self, url: str) -> None:
        """Validate the Elasticsearch URL."""
        try:
            url_parsed = urlparse(url)
            if not url_parsed.scheme or not url_parsed.netloc:
                raise ValueError("Invalid URL structure")
            if url_parsed.scheme not in ("http", "https"):
                raise ValueError("URL must use http or https")
        except Exception as e:
            raise SaasException(f"Invalid Elasticsearch URL: {e}") from e

    @property
    def cert_content(self) -> str:
        """Get the certificate content for the Elasticsearch client."""
        return self.get_config("ssl_content")

    @property
    def client(self) -> Elasticsearch:
        """Get or create Elasticsearch client."""
        if self._client is None:
            Log.debug("Creating Elasticsearch client")
            elasticsearch_url = self.get_config("elasticsearch_url")
            self._validate_url(elasticsearch_url)
            client_config = {
                "hosts": [elasticsearch_url],
                "api_key": self.get_config("api_key"),
                "request_timeout": API_TIMEOUT,
                "verify_certs": self.verify_ssl,
            }

            if self.verify_ssl:
                cert_content = self.cert_content
                if cert_content and cert_content.strip():
                    try:
                        ssl_context = ssl.create_default_context(cadata=cert_content)
                        client_config["ssl_context"] = ssl_context
                    except ssl.SSLError as e:
                        Log.error(f"Invalid SSL certificate content: {e}")
                        raise SaasException(f"Invalid SSL certificate: {e}") from e

            try:
                self._client = Elasticsearch(**client_config)
                if not self._client.ping():
                    raise SaasException(
                        "Unable to connect to Elasticsearch server"
                    )
                Log.debug("Successfully connected to Elasticsearch")

            except ESConnectionError as e:
                Log.error(f"Failed to connect to Elasticsearch: {e}")
                raise SaasException(f"Connection failed: {e}") from e
            except AuthenticationException as e:
                Log.error(f"Authentication failed: {e}")
                raise SaasException(
                    "Authentication failed. Check admin credentials."
                ) from e
            except Exception as e:
                Log.error(
                    f"Unexpected error creating Elasticsearch client: {e}"
                )
                raise SaasException(
                    f"Failed to create Elasticsearch client: {e}"
                ) from e

        return self._client

    @property
    def can_rollback(self) -> bool:
        """Check if password rollback is supported."""
        return self._can_rollback

    @can_rollback.setter
    def can_rollback(self, value: bool):
        """Set the rollback capability flag."""
        self._can_rollback = value

    def _verify_user_exists(self):
        """Verify that the target user exists in Elasticsearch."""
        try:
            self.client.security.get_user(username=self.user.username.value)
            Log.debug(f"User {self.user.username.value} found in Elasticsearch")
            self.can_rollback = True

        except AuthorizationException as e:
            Log.error(f"Authorization failed when changing password: {e}")
            raise SaasException(f"Authorization failed: {e}") from e
        except NotFoundError as e:
            Log.error(
                f"User {self.user.username.value} not found in Elasticsearch"
            )
            raise SaasException(
                f"User '{self.user.username.value}' does not exist "
                f"in Elasticsearch"
            ) from e
        except Exception as e:
            Log.error(f"Error verifying user existence: {e}")
            raise SaasException(
                f"Failed to verify user existence: {e}"
            ) from e

    def _change_user_password(self, password: Secret):
        """Change the password for the specified user."""
        username = self.user.username.value

        Log.info(f"Changing password for Elasticsearch user: {username}")
        try:
            self._verify_user_exists()
            self.client.security.change_password(
                username=username,
                password=password.value
            )
            Log.info(f"Password changed successfully for user: {username}")
            self.client.close()
            self._client = None
        except AuthorizationException as e:
            Log.error(f"Authorization failed when changing password: {e}")
            raise SaasException(f"Authorization failed: {e}") from e
        except RequestError as e:
            self._can_rollback = True
            Log.error(f"Invalid request when changing password: {e}")
            raise SaasException(
                f"Invalid password change request: {e}"
            ) from e
        except Exception as e:
            self._can_rollback = True
            Log.error(f"Unexpected error changing password: {e}")
            raise SaasException(f"Failed to change password: {e}") from e

    def change_password(self):
        """Change the password for the Elasticsearch user.
        
        This method connects to Elasticsearch using admin credentials
        and changes the password for the specified user.
        """
        if self.user.new_password is None:
            raise SaasException(
                "Cannot change password. No new password provided."
            )

        Log.info("Starting password change for Elasticsearch user")
        self._change_user_password(self.user.new_password)
        Log.debug(
            f"Password change completed successfully for user "
            f"{self.user.username.value}"
        )

    def rollback_password(self):
        """Rollback the password change for the Elasticsearch user.
        
        This method reverts the password to the previous value.
        """
        if self.user.prior_password is None:
            raise SaasException(
                "Cannot rollback password. No prior password available."
            )

        Log.info("Rolling back password change for Elasticsearch user")
        assert self.user.prior_password is not None  # Type narrowing for mypy
        self._change_user_password(self.user.prior_password)
        Log.debug(
            f"Password rollback completed successfully for user "
            f"{self.user.username.value}"
        )
