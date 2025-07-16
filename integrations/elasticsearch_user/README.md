# Elasticsearch User Plugin

## Overview

The Elasticsearch User Plugin enables password rotation for Elasticsearch users through Keeper's PAM (Privileged Access Management) system. This plugin connects to an Elasticsearch cluster using administrator credentials and rotates passwords for specified users.

## Features

- **Password Rotation**: Change passwords for Elasticsearch users
- **Password Rollback**: Revert password changes if needed
- **SSL Support**: Configurable SSL certificate verification
- **Error Handling**: Comprehensive error handling and logging
- **User Validation**: Verifies user existence before attempting password changes

## Prerequisites

- Elasticsearch cluster with security features enabled
- Administrator account with `manage_security` privilege
- Python `elasticsearch` package (automatically installed via requirements)

## Configuration

The plugin requires the following configuration parameters:

### Required Fields

| Field | Description |
|-------|-------------|
| **Admin Username** | Username of an administrator with permission to change user passwords |
| **Admin Password** | Password for the Elasticsearch admin user |
| **Elasticsearch URL** | The URL to the Elasticsearch server (e.g., `https://localhost:9200`) |

### Optional Fields

| Field | Description | Default |
|-------|-------------|---------|
| **Verify SSL** | Whether to validate SSL certificates | `True` |

## SSL Configuration

The plugin supports two SSL verification modes:

- **True**: Validates SSL certificates (recommended for production)
- **False**: Allows self-signed certificates (useful for development/testing)

## Required Elasticsearch Permissions

The admin user must have the following privileges:

- `manage_security` - Required to change user passwords
- `manage_users` - Required to verify user existence

## Usage

1. **Create Configuration Record**: Set up a configuration record in Keeper with the required admin credentials and Elasticsearch URL
2. **Create User Record**: Create a PAM user record for the Elasticsearch user whose password you want to rotate
3. **Link Records**: Associate the user record with the configuration record
4. **Execute Rotation**: Run the password rotation through Keeper's PAM system

## Supported Operations

### Password Change
Changes the password for the specified Elasticsearch user using the `security.change_password` API.

### Password Rollback
Reverts the password to the previous value if the rotation needs to be undone.

## Error Handling

The plugin handles various error scenarios:

- **Connection Errors**: Network connectivity issues
- **Authentication Errors**: Invalid admin credentials
- **User Not Found**: Target user doesn't exist in Elasticsearch
- **Permission Errors**: Insufficient privileges
- **SSL Errors**: Certificate validation failures

## Logging

The plugin provides detailed logging for:

- Connection establishment
- User validation
- Password change operations
- Error conditions
- Rollback operations

## Security Considerations

- Store admin credentials securely in Keeper vault
- Use the principle of least privilege for admin accounts
- Enable SSL verification in production environments
- Monitor audit logs for password rotation activities

## Troubleshooting

### Common Issues

**Connection Failed**
- Verify the Elasticsearch URL is correct and accessible
- Check network connectivity
- Verify SSL settings match your Elasticsearch configuration

**Authentication Failed**
- Verify admin username and password are correct
- Ensure the admin user has required permissions

**User Not Found**
- Verify the target username exists in Elasticsearch
- Check for typos in the username

**SSL Certificate Errors**
- Set "Verify SSL" to "False" for self-signed certificates
- Ensure proper SSL certificates are configured for production

## API Reference

The plugin uses the Elasticsearch Python client's security API:

```python
# Change password
client.security.change_password(
    username="target_user",
    password="new_password"
)

# Get user (for validation)
client.security.get_user(username="target_user")
```

## Version Compatibility

- Elasticsearch 7.x and 8.x
- Python 3.7+
- elasticsearch-py client library

## Support

For issues and support:
- Email: pam@keepersecurity.com
- Check Elasticsearch server logs for additional error details
- Verify network connectivity and permissions 