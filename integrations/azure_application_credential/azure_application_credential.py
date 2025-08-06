"""Azure Application Credential SaaS plugin for password rotation."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, List, TYPE_CHECKING

from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.applications.item.add_password.add_password_post_request_body import AddPasswordPostRequestBody
from msgraph.generated.applications.item.remove_password.remove_password_post_request_body import RemovePasswordPostRequestBody
from msgraph.generated.models.password_credential import PasswordCredential

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_plugins import SaasPluginBase
from kdnrm.saas_type import ReturnCustomField, SaasConfigItem, Secret

if TYPE_CHECKING:  # pragma: no cover
    from keeper_secrets_manager_core.dto.dtos import Record
    from kdnrm.saas_type import SaasUser

# Constants
SCOPES = ['https://graph.microsoft.com/.default']
EXPIRATION_DAYS = 90

class SaasPlugin(SaasPluginBase):
    """Azure Application Credential rotation plugin.
    
    This plugin handles the rotation of client secrets for Azure Application
    Registrations using the Microsoft Graph API.
    """

    name = "Azure Application Credential"
    summary = "Rotate client secret for Azure Application Registration."
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
        """Initialize the Azure Application Credential plugin.
        
        Args:
            user: The SaaS user object containing user information
            config_record: Configuration record with Azure credentials
            provider_config: Optional provider-specific configuration
            force_fail: Whether to force failure for testing purposes
        """
        super().__init__(user, config_record, provider_config, force_fail)
        self._client = None

    @classmethod
    def requirements(cls) -> List[str]:
        """Return required Python packages for this plugin.
        
        Returns:
            List of required package names
        """
        return ["azure-identity", "msgraph-sdk"]

    @classmethod
    def config_schema(cls) -> List[SaasConfigItem]:
        """Return the configuration schema for this plugin.
        
        Returns:
            List of configuration items required for Azure authentication
        """
        return [
            SaasConfigItem(
                id="tenant_id",
                label="Tenant ID",
                desc="Azure Active Directory tenant ID (Directory ID)",
                required=True,
                is_secret=True
            ),
            SaasConfigItem(
                id="client_id",
                label="Client ID",
                desc="Application (client) ID from Azure App Registration",
                required=True,
                is_secret=True
            ),
            SaasConfigItem(
                id="client_secret",
                label="Client Secret",
                desc="Client secret value for authentication",
                required=True,
                is_secret=True
            ),
            SaasConfigItem(
                id="object_id",
                label="Object ID",
                desc="Object ID of the Azure Application Registration",
                required=True,
                is_secret=True
            ),
        ]

    @property
    def client(self) -> GraphServiceClient:
        """Get or create the Microsoft Graph client.
        
        Returns:
            Configured GraphServiceClient instance
            
        Raises:
            SaasException: If client creation fails
        """
        if self._client is None:
            Log.debug("Creating Microsoft Graph client with client credentials")
            
            try:
                tenant_id = self.get_config("tenant_id")
                client_id = self.get_config("client_id")
                client_secret = self.get_config("client_secret")
                
                # Create credentials using client credentials flow
                credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                
                # Initialize Graph client
                self._client = GraphServiceClient(
                    credentials=credential,
                    scopes=SCOPES
                )
                
            except ValueError as ve:
                Log.error(f"Error while creating Microsoft Graph client: {ve}")
                raise SaasException(
                    f"Error while creating Microsoft Graph client: {str(ve)}"
                ) from ve
            except Exception as e:
                Log.error(f"Failed to create Microsoft Graph client: {e}")
                raise SaasException(
                    f"Failed to create Microsoft Graph client: {str(e)}"
                ) from e
        else:
            Log.debug("Microsoft Graph client already created")

        return self._client

    def get_field_value(self, field_label: str) -> str:
        """Get value from user fields by label.
        
        Args:
            field_label: The label of the field to retrieve
            
        Returns:
            The field value
            
        Raises:
            SaasException: If the field is not found
        """
        for field in self.user.fields:
            if field.label == field_label:
                if field.values and len(field.values) > 0:
                    return field.values[0]
        raise SaasException(
            f"Required field '{field_label}' not found in user fields"
        )

    @property
    def can_rollback(self) -> bool:
        """Check if password rollback is supported.
        
        Azure Application passwords cannot be rolled back as the old secret
        cannot be restored once deleted.
        
        Returns:
            False - rollback is not supported
        """
        return False

    async def _delete_client_secret_async(self, object_id: str) -> None:
        """Delete an existing client secret from the Azure Application.
        
        Args:
            object_id: The Object ID of the Azure Application
            
        Raises:
            SaasException: If the deletion fails
        """
        key_uid = self._get_user_fields("key_uid")
        Log.debug("Deleting client secret with key ID")

        remove_request_body = RemovePasswordPostRequestBody()
        remove_request_body.key_id = uuid.UUID(key_uid)

        try:
            await self.client.applications.by_application_id(object_id).remove_password.post(remove_request_body)
            Log.debug("Successfully deleted client secret")

        except Exception as e:
            Log.error(f"Failed to delete client secret: {e}")
            raise SaasException(
                f"Failed to delete client secret: {str(e)}"
            ) from e

    async def _create_client_secret_async(self, object_id: str, display_name: str):
        """Create a new client secret for the Azure Application.
        
        Args:
            object_id: The Object ID of the Azure Application
            display_name: The display name for the new client secret
            
        Returns:
            The result object containing the new secret details
            
        Raises:
            SaasException: If the creation fails
        """
        Log.debug(
            f"Creating new client secret with display name: {display_name}"
        )
        
        add_request_body = AddPasswordPostRequestBody()
        password_credential = PasswordCredential()
        password_credential.display_name = display_name
        
        # Set start and end datetime as datetime objects
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(days=EXPIRATION_DAYS)
        
        password_credential.start_date_time = start_time
        password_credential.end_date_time = end_time
        
        add_request_body.password_credential = password_credential
        
        try:
            result = await self.client.applications.by_application_id(object_id).add_password.post(add_request_body)
            Log.debug("Successfully created new client secret")
            return result
        except Exception as e:
            Log.error(f"Failed to create new client secret: {e}")
            raise SaasException(
                f"Failed to create new client secret: {str(e)}"
            ) from e

    async def _rotate_secret_async(self, object_id: str, display_name: str):
        """Perform the complete secret rotation asynchronously.
        
        Args:
            object_id: The Object ID of the Azure Application
            display_name: The display name for the new client secret
            
        Returns:
            The result object containing the new secret details
        """
        # Delete the old client secret first
        await self._delete_client_secret_async(object_id)
        
        # Create the new client secret
        result = await self._create_client_secret_async(object_id, display_name)
        
        return result

    def _get_user_fields(self, field_label: str) -> str:
        """Get value from user fields by label.
        
        Args:
            field_label: The label of the field to retrieve
            
        Returns:
            The field value
            
        Raises:
            SaasException: If the field is not found
        """
        for field in self.user.fields:
            if field.label == field_label:
                if field.values and len(field.values) > 0:
                    return field.values[0]
        raise SaasException(
            f"Required field '{field_label}' not found in user fields"
        )

    def change_password(self) -> None:
        """Rotate the client secret for the Azure Application.
        Raises:
            SaasException: If any step of the rotation process fails
        """
        Log.info("Starting Azure Application credential rotation")

        try:
            object_id = self.get_config("object_id")
            display_name = self._get_user_fields("display_name")

            # Use a single event loop for both operations
            result = asyncio.run(self._rotate_secret_async(object_id, display_name))

            # Store return fields with the new secret information
            self.add_return_field(ReturnCustomField(
                label="display_name",
                type="text",
                value=result.display_name
            ))

            self.add_return_field(ReturnCustomField(
                label="key_uid",
                type="text",
                value=str(result.key_id)
            ))

            self.add_return_field(ReturnCustomField(
                label="client_secret",
                type="secret",
                value=Secret(result.secret_text)
            ))

            Log.info(
                "Azure Application credential rotation completed successfully"
            )
            
        except Exception as e:
            Log.error(f"Azure Application credential rotation failed: {e}")
            raise SaasException(
                f"Credential rotation failed: {str(e)}"
            ) from e

    def rollback_password(self) -> None:
        """Rollback the password change for the Azure Application.
        
        Note: Azure doesn't support true password rollback as the old client
        secret cannot be restored once deleted.
        
        Raises:
            SaasException: Always raised as rollback is not supported
        """
        Log.info("Rollback requested for Azure Application credential")
        raise SaasException(
            "Rollback is not supported for Azure Application credentials. "
            "The old client secret cannot be restored once deleted."
        )