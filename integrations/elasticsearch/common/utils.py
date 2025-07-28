import ssl
from typing import Optional
from urllib.parse import urlparse

from kdnrm.exceptions import SaasException
from kdnrm.log import Log


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


def should_verify_ssl(verify_ssl_config_value: str) -> bool:
    """Check if SSL verification should be enabled based on config value.
    
    Args:
        verify_ssl_config_value: The config value for SSL verification
        
    Returns:
        bool: True if SSL should be verified, False otherwise
    """
    return str(verify_ssl_config_value) == "True"


def create_ssl_context(cert_content: Optional[str], verify_ssl: bool) -> Optional[ssl.SSLContext]:
    """Create SSL context if custom certificate is provided and SSL verification is enabled.
    
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


def build_elasticsearch_client_config(
    hosts: list,
    verify_ssl: bool,
    cert_content: Optional[str] = None,
    api_key: Optional[str] = None,
    basic_auth: Optional[tuple] = None,
    request_timeout: int = 30,
    max_retries: int = 3
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
    ssl_context = create_ssl_context(cert_content, verify_ssl)
    if ssl_context:
        config["ssl_context"] = ssl_context

    return config
