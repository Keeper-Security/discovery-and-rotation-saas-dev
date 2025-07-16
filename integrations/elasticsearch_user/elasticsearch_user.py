from __future__ import annotations
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import Secret, SaasConfigItem, SaasConfigEnum
from kdnrm.exceptions import SaasException
from typing import List, TYPE_CHECKING
from kdnrm.log import Log
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    NotFoundError,
    RequestError,
    ConnectionError,
)
import ssl

if TYPE_CHECKING:  # pragma: no cover
    from kdnrm.saas_type import SaasUser
    from keeper_secrets_manager_core.dto.dtos import Record


class SaasPlugin(SaasPluginBase):

    name = "Elasticsearch User"
    summary = "Change a user password in Elasticsearch."
    readme = "README.md"
    author = "Keeper Security"
    email = "pam@keepersecurity.com"

    def __init__(self, user: SaasUser, config_record: Record, provider_config=None, force_fail=False):
        super().__init__(user, config_record, provider_config, force_fail)
        self.user = user
        self.config_record = config_record
        self._client = None

    @classmethod
    def requirements(cls) -> List[str]:
        return ["elasticsearch"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        return [
            SaasConfigItem(
                id="api_key",
                label="API Key",
                desc="API Key for the Elasticsearch admin user.",
                type="secret",
                is_secret=True,
                required=False
            ),
            SaasConfigItem(
                id="elasticsearch_url",
                label="Elasticsearch URL",
                desc="The URL to the Elasticsearch server (e.g., https://localhost:9200).",
                type="url",
                required=True
            ),
            SaasConfigItem(
                id="verify_ssl",
                label="Verify SSL",
                desc="Verify that the SSL certificate is valid: "
                     "'True' will validate certificates, "
                     "'False' will allow self-signed certificates.",
                type="enum",
                required=False,
                default_value="True",
                enum_values=[
                    SaasConfigEnum(
                        value="False",
                        desc="Do not validate the SSL certificate. This will allow self-signed certificates."
                    ),
                    SaasConfigEnum(
                        value="True",
                        desc="Validate the SSL certificate. Self-signed certificates are not allowed."
                    ),
                ]
            )
        ]

    @property
    def client(self) -> Elasticsearch:
        """Get or create Elasticsearch client."""
        if self._client is None:
            Log.debug("Creating Elasticsearch client")

            # Configure SSL context
            if self.get_config("verify_ssl") == "False":
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context = None

            try:
                self._client = Elasticsearch(
                    hosts=[self.get_config("elasticsearch_url")],
                    api_key=self.get_config("api_key"),
                    ssl_context=ssl_context,
                    verify_certs=(self.get_config("verify_ssl") == "True"),
                    request_timeout=30
               )

                # Test the connection
                if not self._client.ping():
                    raise SaasException("Unable to connect to Elasticsearch server")

                Log.debug("Successfully connected to Elasticsearch")

            except ConnectionError as e:
                Log.error(f"Failed to connect to Elasticsearch: {e}")
                raise SaasException(f"Connection failed: {e}")
            except AuthenticationException as e:
                Log.error(f"Authentication failed: {e}")
                raise SaasException("Authentication failed. Check admin credentials.")
            except Exception as e:
                Log.error(f"Unexpected error creating Elasticsearch client: {e}")
                raise SaasException(f"Failed to create Elasticsearch client: {e}")

        return self._client

    @property
    def can_rollback(self) -> bool:
        """
        Check if password rollback is supported.
        For Elasticsearch, we assume rollback is always possible since we maintain the previous password.
        """
        try:
            # Verify we can connect and have the necessary permissions
            self.client.security.get_user(username=self.user.username.value)
            Log.debug("Rollback capability verified - user exists and we have permissions")
            return True
        except NotFoundError:
            Log.error(f"User {self.user.username.value} not found in Elasticsearch")
            return False
        except Exception as e:
            Log.error(f"Error checking rollback capability: {e}")
            return False

    def _verify_user_exists(self):
        """Verify that the target user exists in Elasticsearch."""
        try:
            user_info = self.client.security.get_user(username=self.user.username.value)
            Log.debug(f"User {self.user.username.value} found in Elasticsearch")
            return True
        except NotFoundError:
            Log.error(f"User {self.user.username.value} not found in Elasticsearch")
            raise SaasException(f"User '{self.user.username.value}' does not exist in Elasticsearch")
        except Exception as e:
            Log.error(f"Error verifying user existence: {e}")
            raise SaasException(f"Failed to verify user existence: {e}")

    def _change_user_password(self, password: Secret):
        """Change the password for the specified user."""
        username = self.user.username.value
        
        Log.info(f"Changing password for Elasticsearch user: {username}")
        
        try:
            # First verify the user exists
            self._verify_user_exists()
            
            # Change the password using the Elasticsearch security API
            response = self.client.security.change_password(
                username=username,
                password=password.value
            )
            
            Log.info(f"Password changed successfully for user: {username}")
            Log.debug(f"Elasticsearch response: {response}")
            
        except NotFoundError:
            Log.error(f"User {username} not found")
            raise SaasException(f"User '{username}' does not exist in Elasticsearch")
        except RequestError as e:
            Log.error(f"Invalid request when changing password: {e}")
            raise SaasException(f"Invalid password change request: {e}")
        except AuthenticationException:
            Log.error("Authentication failed during password change")
            raise SaasException("Authentication failed. Check admin credentials.")
        except Exception as e:
            Log.error(f"Unexpected error changing password: {e}")
            raise SaasException(f"Failed to change password: {e}")

    def change_password(self):
        """
        Change the password for the Elasticsearch user.
        This method connects to Elasticsearch using admin credentials
        and changes the password for the specified user.
        """
        Log.info("Starting password change for Elasticsearch user")
        self._change_user_password(self.user.new_password)
        Log.debug(f"Password change completed successfully for user {self.user.username.value}")

    def rollback_password(self):
        """
        Rollback the password change for the Elasticsearch user.
        This method reverts the password to the previous value.
        """
        if self.user.prior_password is None:
            raise SaasException("Cannot rollback password. No prior password available.")

        Log.info("Rolling back password change for Elasticsearch user")
        assert self.user.prior_password is not None  # Type narrowing for mypy
        self._change_user_password(self.user.prior_password)
        Log.debug(f"Password rollback completed successfully for user {self.user.username.value}")
