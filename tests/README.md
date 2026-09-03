# Integration Testing

This directory contains tools for testing all SaaS rotation plugins in the `integrations` directory.

## Overview

The `test_all_integrations.py` script automatically discovers and runs unit tests for all plugins in the integrations directory. This provides a quick way to verify that code changes to the development tool haven't broken existing integrations.

## Running All Integration Tests

To run tests for all integrations:

```shell
cd /path/to/discovery-and-rotation-saas-dev
python -m pytest tests/test_all_integrations.py -v
```

Or using unittest directly:

```shell
python -m unittest tests.test_all_integrations
```

## What the Test Suite Does

For each integration plugin directory, the test suite:

1. **Discovers test files** - Finds all `*_test.py` files in each integration directory
2. **Installs dependencies** - If `requirements_test.txt` exists, installs test dependencies
3. **Runs unit tests** - Executes all test cases using Python's unittest framework
4. **Calculates coverage** - Reports test coverage percentage (if `coverage` package is available)
5. **Reports results** - Provides a summary of passed/failed tests

## Test Output

The test suite provides detailed output including:

- ✅ Passed integrations with coverage percentage
- ❌ Failed integrations
- ⚠️ Integrations without tests
- 📊 Coverage statistics per integration

Example output:

```
============================================================
Testing integration: splunk_users
============================================================
  📦 Installing test dependencies from requirements_test.txt...
    ✅ Dependencies installed
  Loading tests from: splunk_users_test.py
  test_change_password_success ... ok
  test_config_schema ... ok
  📊 Coverage: 87.3% (55/63 statements)
  ✅ splunk_users: All tests passed

============================================================
TEST SUMMARY
============================================================
✅ splunk_users: PASSED (87.3% coverage)
✅ jfrog_users: PASSED (91.2% coverage)
❌ aws_cognito: FAILED

Total integrations: 12
Passed: 10
Failed: 2
No tests: 0
```

## Writing Plugin Tests

### Test File Structure

Each integration should have a test file following this pattern:

```
integrations/
└── my_plugin/
    ├── my_plugin.py           # Main plugin file
    ├── my_plugin_test.py      # Unit tests
    ├── requirements_test.txt  # Test dependencies (optional)
    └── README.md
```

### Basic Test Template

```python
from __future__ import annotations
import unittest
import sys
import os
from unittest.mock import MagicMock, patch
from typing import Optional

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the plugin
from my_plugin import SaasPlugin

# Test constants
DEFAULT_API_URL = "https://api.example.com"
DEFAULT_USERNAME = "testuser"
DEFAULT_NEW_PASSWORD = "NewPassword123!"

class MyPluginTestBase(unittest.TestCase):
    """Base class for plugin tests."""
    
    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")
    
    def create_user(self, username: str, new_password: str, 
                    prior_password: Optional[str] = None):
        """Helper to create a SaasUser for testing."""
        return SaasUser(
            username=Secret(username),
            new_password=Secret(new_password) if new_password else None,
            prior_password=Secret(prior_password) if prior_password else None
        )
    
    def create_config_record(self, config_fields: list):
        """Helper to create a mock config record."""
        return MockRecord(custom=config_fields)

class MyPluginTest(MyPluginTestBase):
    
    def test_requirements(self):
        """Test that plugin requirements are correctly defined."""
        req_list = SaasPlugin.requirements()
        self.assertIn("requests", req_list)
    
    def test_config_schema(self):
        """Test configuration schema has required fields."""
        schema = SaasPlugin.config_schema()
        field_ids = [field.id for field in schema]
        self.assertIn("api_url", field_ids)
        self.assertIn("api_token", field_ids)
    
    @patch('my_plugin.requests.post')
    def test_change_password_success(self, mock_post):
        """Test successful password change."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        # Create plugin instance
        user = self.create_user(DEFAULT_USERNAME, DEFAULT_NEW_PASSWORD)
        config_fields = [
            {'type': 'url', 'label': 'API URL', 'value': [DEFAULT_API_URL]},
            {'type': 'secret', 'label': 'API Token', 'value': ['token123']}
        ]
        config_record = self.create_config_record(config_fields)
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        # Test password change
        plugin.change_password()
        
        # Verify API was called correctly
        mock_post.assert_called_once()
    
    @patch('my_plugin.requests.post')
    def test_change_password_user_not_found(self, mock_post):
        """Test password change when user doesn't exist."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response
        
        user = self.create_user(DEFAULT_USERNAME, DEFAULT_NEW_PASSWORD)
        config_record = self.create_config_record([
            {'type': 'url', 'label': 'API URL', 'value': [DEFAULT_API_URL]},
            {'type': 'secret', 'label': 'API Token', 'value': ['token123']}
        ])
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("not found", str(context.exception))

if __name__ == '__main__':
    unittest.main()
```

### Key Testing Patterns

Based on the existing integration tests, here are common patterns:

#### 1. Base Test Class Pattern

Create a base test class with common helper methods:

```python
class MyPluginTestBase(unittest.TestCase):
    def setUp(self):
        Log.init()
        Log.set_log_level("DEBUG")
    
    def create_user(self, username, new_password, prior_password=None):
        """Helper to create test users."""
        return SaasUser(
            username=Secret(username),
            new_password=Secret(new_password) if new_password else None,
            prior_password=Secret(prior_password) if prior_password else None
        )
    
    def create_config_record(self, config_fields):
        """Helper to create mock config records."""
        return MockRecord(custom=config_fields)
```

#### 2. Mock External Services

Use `@patch` decorator to mock API calls:

```python
@patch('my_plugin.requests.Session')
def test_api_call(self, mock_session_class):
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_session.request.return_value = mock_response
    
    # Test your plugin
```

#### 3. Test Configuration Schema

Always test that the config schema includes required fields:

```python
def test_config_schema(self):
    schema = SaasPlugin.config_schema()
    field_ids = [field.id for field in schema]
    
    # Check required fields exist
    self.assertIn("api_url", field_ids)
    self.assertIn("api_token", field_ids)
    
    # Verify secret fields are marked correctly
    token_field = next(f for f in schema if f.id == "api_token")
    self.assertTrue(token_field.is_secret)
```

#### 4. Test Error Conditions

Test various failure scenarios:

```python
def test_change_password_user_not_found(self):
    """Test 404 error handling."""
    # Setup mock to return 404
    # Assert SaasException is raised
    
def test_change_password_unauthorized(self):
    """Test 401/403 authentication errors."""
    
def test_change_password_timeout(self):
    """Test connection timeout handling."""
    
def test_change_password_no_new_password(self):
    """Test error when new password is missing."""
```

#### 5. Test Rollback Functionality

If your plugin supports rollback:

```python
@patch('my_plugin.api_client')
def test_rollback_password_success(self, mock_api):
    plugin = self.plugin(prior_password=Secret("OldPass123"))
    plugin.can_rollback = True
    
    plugin.rollback_password()
    
    # Verify API was called with prior password
    mock_api.update_password.assert_called_with(password="OldPass123")

def test_rollback_no_prior_password(self):
    plugin = self.plugin()  # No prior password
    
    with self.assertRaises(SaasException):
        plugin.rollback_password()
```

#### 6. Test SSL/TLS Configuration

For plugins with SSL options:

```python
def test_ssl_verification_enabled(self):
    """Test SSL verification is enabled correctly."""
    
def test_ssl_verification_disabled(self):
    """Test SSL can be disabled."""
    
def test_custom_ssl_certificate(self):
    """Test custom SSL certificate handling."""
```

### Test Coverage Requirements

- Minimum 70% code coverage required for all plugins
- Run coverage locally before submitting PR:

```shell
pip install pytest pytest-cov
pytest --cov=my_plugin --cov-report=term-missing my_plugin_test.py
```

### Common Test Utilities

The `plugin_dev.test_base` module provides:

- `MockRecord` - Mock configuration record for testing
- Test fixtures and helpers

### Best Practices

1. **Use descriptive test names** - `test_change_password_user_not_found` is better than `test_error`
2. **Test happy path first** - Start with `test_change_password_success`
3. **Test all error conditions** - 401, 403, 404, 500, timeouts, connection errors
4. **Mock external dependencies** - Never make real API calls in tests
5. **Test edge cases** - Empty passwords, special characters, missing fields
6. **Verify error messages** - Check that exceptions contain helpful error messages
7. **Test rollback when supported** - If plugin implements rollback, test it
8. **Isolate tests** - Each test should be independent and not affect others

## Troubleshooting

### Import Errors

If you get import errors, ensure:
- Plugin file is in the same directory as the test
- Test file uses `sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))`

### Missing Dependencies

Add test dependencies to `requirements_test.txt`:

```
requests-mock==1.11.0
responses==0.24.0
```

### Coverage Not Showing

Install coverage package:

```shell
pip install coverage
```

Run coverage manually:

```shell
coverage run -m unittest integrations.my_plugin.my_plugin_test
coverage report --omit="*_test.py"
```