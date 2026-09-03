# Testing Guide for SaaS Rotation Plugins

A unit test is required for all plugins. 
The test has a minimum 70% coverage limit.
If the coverage is less than 70%, the pull request will not be accepted.

## Table of Contents

- [Quick Start](#quick-start)
- [Testing Your Plugin Locally](#testing-your-plugin-locally)
- [Test File Structure](#test-file-structure)
- [Mock Record](#mock-record)
- [Complete Test Example](#complete-test-example)
- [Common Testing Patterns](#common-testing-patterns)
- [Testing Checklist](#testing-checklist)
- [Best Practices](#best-practices)

## Quick Start

To test your plugin locally with coverage:

```shell
cd /path/to/your_plugin_directory
pip install pytest pytest-cov
pytest --cov=your_plugin --cov-report=term-missing your_plugin_test.py
```

The output will show coverage percentage and highlight any lines that are not covered.

## Testing Your Plugin Locally

### Install Test Dependencies

If your plugin requires specific packages for testing (like `requests-mock`, `responses`, etc.), create a `requirements_test.txt` file:

```text
requests-mock==1.11.0
responses==0.24.0
```

Then install:

```shell
pip install -r requirements_test.txt
```

### Run Tests

Using pytest:

```shell
pytest your_plugin_test.py -v
```

Using unittest:

```shell
python -m unittest your_plugin_test.py
```

### Check Coverage

#### Method 1: Using pytest-cov (Recommended)

```shell
pytest --cov=your_plugin --cov-report=term-missing your_plugin_test.py
```

Example output:

```
========================= test session starts ==========================
platform darwin -- Python 3.11.5, pytest-7.4.3
collected 15 tests

your_plugin_test.py::YourPluginTest::test_requirements PASSED      [  6%]
your_plugin_test.py::YourPluginTest::test_config_schema PASSED     [ 13%]
your_plugin_test.py::YourPluginTest::test_change_password_success PASSED [ 20%]
your_plugin_test.py::YourPluginTest::test_change_password_user_not_found PASSED [ 26%]
...

========================== 15 passed in 2.34s ==========================

----------- coverage: platform darwin, python 3.11.5 -----------
Name                   Stmts   Miss  Cover   Missing
----------------------------------------------------
your_plugin.py           120      8    93%   45-47, 89-92
----------------------------------------------------
TOTAL                    120      8    93%
```

**Understanding the output:**
- `Stmts`: Total number of executable statements
- `Miss`: Number of statements not covered by tests
- `Cover`: Coverage percentage (must be ≥70%)
- `Missing`: Line numbers that are not covered

#### Method 2: Using coverage directly

```shell
# Run tests with coverage
coverage run -m pytest your_plugin_test.py

# Generate report
coverage report --omit="*_test.py"

# Generate detailed HTML report
coverage html --omit="*_test.py"
# Open htmlcov/index.html in browser to see detailed coverage
```

Example report output:

```
Name               Stmts   Miss  Cover
--------------------------------------
your_plugin.py       120      8    93%
--------------------------------------
TOTAL                120      8    93%
```

#### Method 3: Using unittest with coverage

```shell
coverage run -m unittest your_plugin_test.py
coverage report --omit="*_test.py"
```

#### Detailed Example: Step-by-Step

Let's say you have a plugin called `splunk_users`:

```shell
# 1. Navigate to your plugin directory
cd integrations/splunk_users

# 2. Install coverage tools (if not already installed)
pip install pytest pytest-cov coverage

# 3. Run tests with coverage
pytest --cov=splunk_users --cov-report=term-missing splunk_users_test.py

# Output will show:
========================= test session starts ==========================
collected 42 tests

splunk_users_test.py::SplunkUserPluginTest::test_requirements PASSED
splunk_users_test.py::SplunkUserPluginTest::test_config_schema PASSED
splunk_users_test.py::SplunkUserPluginTest::test_change_password_success_https PASSED
splunk_users_test.py::SplunkUserPluginTest::test_change_password_user_not_found PASSED
splunk_users_test.py::SplunkUserPluginTest::test_change_password_http_error_403 PASSED
splunk_users_test.py::SplunkUserPluginTest::test_rollback_password_success PASSED
... (36 more tests)

========================== 42 passed in 3.21s ==========================

----------- coverage: -----------
Name                   Stmts   Miss  Cover   Missing
----------------------------------------------------
splunk_users.py          187      12    94%   234-236, 312-315, 401-404
----------------------------------------------------
TOTAL                    187      12    94%
```

**Reading the results:**
- ✅ **94% coverage** - PASS (exceeds 70% minimum)
- Lines 234-236, 312-315, 401-404 are not covered
- You should add tests for those lines or verify they're edge cases

#### What to do if coverage is below 70%

If you see:

```
----------- coverage: -----------
Name                   Stmts   Miss  Cover   Missing
----------------------------------------------------
your_plugin.py           120     45    62%   45-89, 123-156
----------------------------------------------------
TOTAL                    120     45    62%
```

**This fails the 70% requirement!** Here's how to fix it:

1. **Identify missing lines**: Lines 45-89 and 123-156 are not tested

2. **Check what those lines do**:
   ```shell
   # View the specific lines
   sed -n '45,89p' your_plugin.py
   ```

3. **Write tests to cover them**:
   - If they handle error conditions → add error tests
   - If they handle edge cases → add edge case tests
   - If they're helper methods → call them in tests

4. **Re-run coverage** until you reach ≥70%

#### Generate HTML Coverage Report (Visual View)

For a detailed visual report showing exactly which lines are covered:

```shell
pytest --cov=your_plugin --cov-report=html your_plugin_test.py
open htmlcov/index.html  # macOS
# or
xdg-open htmlcov/index.html  # Linux
```

This creates an interactive HTML report showing:
- Green lines: Covered by tests ✅
- Red lines: Not covered by tests ❌
- Yellow lines: Partially covered (branches)

## Test File Structure

Each plugin directory should contain:

```
your_plugin/
├── your_plugin.py           # Main plugin code
├── your_plugin_test.py      # Unit tests (required)
├── requirements_test.txt    # Test dependencies (optional)
├── config.json              # KSM config (not committed)
└── README.md
```

## Mock Record

To mock the configuration record, use `MockRecord` from `plugin_dev.test_base`. 
It is a subclass of `Record` from the [Keeper Secrets Manager SDK](https://github.com/Keeper-Security/secrets-manager/blob/a95f3a01e55b9552805e65d365d33227ae51fe57/sdk/python/core/keeper_secrets_manager_core/dto/dtos.py#L23).

### Basic MockRecord Usage

```python
from plugin_dev.test_base import MockRecord

config_record = MockRecord(
    custom=[
        {'type': 'url', 'label': 'API URL', 'value': ['https://api.example.com']},
        {'type': 'text', 'label': 'Username', 'value': ['admin']},
        {'type': 'secret', 'label': 'Password', 'value': ['SecurePass123']},
        {'type': 'multiline', 'label': 'SSL Certificate', 'value': ['-----BEGIN CERTIFICATE-----\n...']},
    ]
)
```

### Field Types

Common field types you can use in `MockRecord`:

- `'text'` - Plain text field
- `'secret'` - Sensitive text (passwords, tokens)
- `'url'` - URL field
- `'multiline'` - Multi-line text (certificates, JSON)
- `'enum'` - Enumerated value (like "True"/"False")

## Complete Test Example

Here's a comprehensive test template based on real integration tests:

```python
from __future__ import annotations
import importlib.util
import os
import sys
import unittest
from typing import Optional
from unittest.mock import MagicMock, patch

from kdnrm.exceptions import SaasException
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.secret import Secret
from plugin_dev.test_base import MockRecord

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the plugin file in the current directory
try:
    from your_plugin import SaasPlugin
except ImportError:
    # Alternative import if direct import fails
    spec = importlib.util.spec_from_file_location(
        "your_plugin",
        os.path.join(os.path.dirname(__file__), "your_plugin.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SaasPlugin = module.SaasPlugin

# Test constants
DEFAULT_API_URL = "https://api.example.com"
DEFAULT_API_TOKEN = "test_token_12345"
DEFAULT_USERNAME = "testuser"
DEFAULT_NEW_PASSWORD = "NewPassword123!"
DEFAULT_PRIOR_PASSWORD = "OldPassword123!"


class PluginTestBase(unittest.TestCase):
    """Base class for plugin tests with common helper methods."""

    def setUp(self):
        """Initialize logging for each test."""
        Log.init()
        Log.set_log_level("DEBUG")

    def create_user(
        self,
        username: str,
        new_password: str,
        prior_password: Optional[str] = None,
        fields: Optional[list] = None
    ) -> SaasUser:
        """Create a test user with the given parameters."""
        if fields is None:
            fields = []
        
        return SaasUser(
            username=Secret(username),
            new_password=Secret(new_password) if new_password else None,
            prior_password=Secret(prior_password) if prior_password else None,
            fields=fields
        )

    def create_config_record(self, config_fields: list) -> MockRecord:
        """Create a MockRecord with the given config fields."""
        return MockRecord(custom=config_fields)

    def create_field(
        self,
        field_type: str,
        label: str,
        value: str,
        is_secret: bool = False
    ) -> dict:
        """Create a configuration field."""
        return {
            'type': 'secret' if is_secret else field_type,
            'label': label,
            'value': [value]
        }


class PluginTestUtils:
    """Utility methods for creating test data."""

    @staticmethod
    def create_config_fields(
        api_url: str = DEFAULT_API_URL,
        api_token: str = DEFAULT_API_TOKEN,
        verify_ssl: str = "True"
    ) -> list:
        """Create standard config fields for the plugin."""
        return [
            {'type': 'url', 'label': 'API URL', 'value': [api_url]},
            {'type': 'secret', 'label': 'API Token', 'value': [api_token]},
            {'type': 'enum', 'label': 'Verify SSL', 'value': [verify_ssl]},
        ]


class YourPluginTest(PluginTestBase):
    """Main test class for your plugin."""

    def plugin(
        self,
        prior_password: Optional[Secret] = None,
        field_values: Optional[dict] = None,
        username: Optional[Secret] = None
    ) -> SaasPlugin:
        """Helper method to create a plugin instance for testing."""
        
        if username is None:
            username = Secret(DEFAULT_USERNAME)

        user = self.create_user(
            username=username.value,
            new_password=DEFAULT_NEW_PASSWORD,
            prior_password=prior_password.value if prior_password else None
        )

        if field_values is None:
            field_values = {
                "API URL": DEFAULT_API_URL,
                "API Token": DEFAULT_API_TOKEN,
                "Verify SSL": "True"
            }

        config_fields = PluginTestUtils.create_config_fields(
            api_url=field_values.get("API URL", DEFAULT_API_URL),
            api_token=field_values.get("API Token", DEFAULT_API_TOKEN),
            verify_ssl=field_values.get("Verify SSL", "True")
        )

        config_record = self.create_config_record(config_fields)
        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """Test plugin requirements are correctly defined."""
        req_list = SaasPlugin.requirements()
        self.assertIn("requests", req_list)

    def test_config_schema(self):
        """Test config schema contains all required fields."""
        schema = SaasPlugin.config_schema()
        self.assertGreater(len(schema), 0)
        
        # Check required fields are present
        field_ids = [field.id for field in schema]
        expected_fields = ["api_url", "api_token"]
        for field_id in expected_fields:
            self.assertIn(field_id, field_ids)
        
        # Verify secret fields are marked correctly
        token_field = next(f for f in schema if f.id == "api_token")
        self.assertTrue(token_field.is_secret)

    @patch('your_plugin.requests.Session')
    def test_change_password_success(self, mock_session_class):
        """Test successful password change."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.request.return_value = mock_response

        plugin = self.plugin()
        plugin.change_password()

        # Verify API was called
        self.assertTrue(mock_session.request.called)

    @patch('your_plugin.requests.Session')
    def test_change_password_user_not_found(self, mock_session_class):
        """Test password change when user does not exist."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock 404 response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_session.request.return_value = mock_response

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("not found", str(context.exception).lower())

    @patch('your_plugin.requests.Session')
    def test_change_password_authentication_failed(self, mock_session_class):
        """Test password change with authentication failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock 401 response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_session.request.return_value = mock_response

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("401", str(context.exception))

    @patch('your_plugin.requests.Session')
    def test_change_password_authorization_failed(self, mock_session_class):
        """Test password change with authorization failure."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock 403 response
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_session.request.return_value = mock_response

        plugin = self.plugin()
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("403", str(context.exception))

    def test_change_password_no_new_password(self):
        """Test password change when no new password is provided."""
        user = self.create_user(
            username=DEFAULT_USERNAME,
            new_password=None  # No new password
        )
        
        config_fields = PluginTestUtils.create_config_fields()
        config_record = self.create_config_record(config_fields)
        plugin = SaasPlugin(user=user, config_record=config_record)
        
        with self.assertRaises(SaasException) as context:
            plugin.change_password()
        
        self.assertIn("No new password", str(context.exception))

    @patch('your_plugin.requests.Session')
    def test_rollback_password_success(self, mock_session_class):
        """Test successful password rollback."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.request.return_value = mock_response
        
        plugin = self.plugin(prior_password=Secret(DEFAULT_PRIOR_PASSWORD))
        plugin.can_rollback = True
        
        plugin.rollback_password()
        
        # Verify rollback was called
        self.assertTrue(mock_session.request.called)

    def test_rollback_password_no_prior_password(self):
        """Test password rollback when no prior password is available."""
        plugin = self.plugin()  # No prior password
        
        with self.assertRaises(SaasException) as context:
            plugin.rollback_password()
        
        self.assertIn("No prior password", str(context.exception))


if __name__ == '__main__':
    unittest.main()
```

## Common Testing Patterns

### 1. Testing HTTP Error Responses

```python
@patch('your_plugin.requests.Session')
def test_http_error_handling(self, mock_session_class):
    """Test various HTTP error codes."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session
    
    # Test different status codes
    error_codes = [400, 401, 403, 404, 500, 503]
    for code in error_codes:
        with self.subTest(code=code):
            mock_response = MagicMock()
            mock_response.status_code = code
            mock_session.request.return_value = mock_response
            
            plugin = self.plugin()
            with self.assertRaises(SaasException):
                plugin.change_password()
```

### 2. Testing SSL/TLS Configuration

```python
@patch('your_plugin.requests.Session')
def test_ssl_verification_disabled(self, mock_session_class):
    """Test with SSL verification disabled."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session
    
    field_values = {
        "API URL": DEFAULT_API_URL,
        "API Token": DEFAULT_API_TOKEN,
        "Verify SSL": "False"
    }
    
    plugin = self.plugin(field_values=field_values)
    # Verify SSL is disabled
    self.assertFalse(plugin.verify_ssl)

@patch('your_plugin.ssl.create_default_context')
def test_custom_ssl_certificate(self, mock_ssl):
    """Test custom SSL certificate handling."""
    mock_context = MagicMock()
    mock_ssl.return_value = mock_context
    
    cert_content = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    field_values = {
        "API URL": DEFAULT_API_URL,
        "API Token": DEFAULT_API_TOKEN,
        "Verify SSL": "True",
        "SSL Certificate": cert_content
    }
    
    plugin = self.plugin(field_values=field_values)
    # Verify certificate was processed
    mock_ssl.assert_called()
```

### 3. Testing Connection Timeouts

```python
from requests.exceptions import Timeout, ConnectionError

@patch('your_plugin.requests.Session')
def test_connection_timeout(self, mock_session_class):
    """Test connection timeout handling."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session
    mock_session.request.side_effect = Timeout("Request timeout")
    
    plugin = self.plugin()
    
    with self.assertRaises(SaasException) as context:
        plugin.change_password()
    
    self.assertIn("timeout", str(context.exception).lower())

@patch('your_plugin.requests.Session')
def test_connection_error(self, mock_session_class):
    """Test connection error handling."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session
    mock_session.request.side_effect = ConnectionError("Cannot connect")
    
    plugin = self.plugin()
    
    with self.assertRaises(SaasException) as context:
        plugin.change_password()
    
    self.assertIn("connect", str(context.exception).lower())
```

### 4. Testing URL Validation

```python
def test_url_validation_valid(self):
    """Test URL validation with valid URLs."""
    valid_urls = [
        "https://api.example.com",
        "http://localhost:8080",
        "https://subdomain.example.com:443"
    ]
    
    for url in valid_urls:
        with self.subTest(url=url):
            # Should not raise exception
            SaasPlugin.validate_url(url)

def test_url_validation_invalid(self):
    """Test URL validation with invalid URLs."""
    invalid_urls = [
        "not-a-url",
        "ftp://unsupported.com",
        "",
        "https://"  # Missing netloc
    ]
    
    for url in invalid_urls:
        with self.subTest(url=url):
            with self.assertRaises(SaasException):
                SaasPlugin.validate_url(url)
```

### 5. Testing Property Access

```python
def test_properties_access(self):
    """Test plugin property accessors."""
    plugin = self.plugin()
    
    # Test URL property
    self.assertEqual(plugin.api_url, DEFAULT_API_URL)
    
    # Test token property (Secret object)
    self.assertEqual(plugin.api_token.value, DEFAULT_API_TOKEN)
    
    # Test boolean property
    self.assertTrue(plugin.verify_ssl)
```

## Testing Checklist

Use this checklist to ensure comprehensive test coverage:

- [ ] **Requirements Test** - `test_requirements()` verifies all dependencies
- [ ] **Config Schema Test** - `test_config_schema()` validates configuration fields
- [ ] **Happy Path** - `test_change_password_success()` tests successful rotation
- [ ] **User Not Found** - Test 404 error when user doesn't exist
- [ ] **Authentication Error** - Test 401 unauthorized
- [ ] **Authorization Error** - Test 403 forbidden
- [ ] **Bad Request** - Test 400 invalid input
- [ ] **Server Error** - Test 500 server errors
- [ ] **Connection Timeout** - Test timeout handling
- [ ] **Connection Error** - Test network connectivity issues
- [ ] **No New Password** - Test error when password is missing
- [ ] **Rollback Success** - Test successful password rollback (if supported)
- [ ] **Rollback No Prior** - Test rollback fails without prior password
- [ ] **SSL Enabled** - Test SSL verification enabled
- [ ] **SSL Disabled** - Test SSL verification disabled
- [ ] **Custom Certificate** - Test custom SSL certificate (if supported)
- [ ] **URL Validation** - Test URL validation logic
- [ ] **Property Access** - Test all property getters

## Best Practices

### 1. Use Descriptive Test Names

✅ Good:
```python
def test_change_password_user_not_found(self):
def test_rollback_password_no_prior_password(self):
```

❌ Bad:
```python
def test_error(self):
def test_case_2(self):
```

### 2. Mock External Dependencies

Always mock API calls, never make real requests:

```python
@patch('your_plugin.requests.Session')
def test_something(self, mock_session):
    # Mock the external API
```

### 3. Test Error Messages

Verify exceptions contain helpful information:

```python
with self.assertRaises(SaasException) as context:
    plugin.change_password()

self.assertIn("User not found", str(context.exception))
```

### 4. Use Helper Methods

Create helper methods in a base test class:

```python
class PluginTestBase(unittest.TestCase):
    def create_user(self, ...):
        # Reusable user creation
    
    def create_config_record(self, ...):
        # Reusable config creation
```

### 5. Test Edge Cases

Don't just test the happy path:

- Empty strings
- None values
- Special characters in passwords
- Missing required fields
- Malformed URLs
- Invalid certificates

### 6. Verify Mock Calls

Check that mocks were called with expected arguments:

```python
mock_session.request.assert_called_once()
mock_session.request.assert_called_with(
    'POST',
    'https://api.example.com/users/testuser/password',
    json={'password': 'NewPassword123!'}
)
```

### 7. Use subTest for Multiple Cases

When testing multiple similar cases:

```python
def test_multiple_urls(self):
    urls = ["https://a.com", "https://b.com", "https://c.com"]
    for url in urls:
        with self.subTest(url=url):
            # Test each URL
```

### 8. Keep Tests Independent

Each test should be able to run independently:

```python
def setUp(self):
    # Reset state before each test
    Log.init()
    Log.set_log_level("DEBUG")
```

## Running Integration Tests

To test all plugins at once:

```shell
cd /path/to/discovery-and-rotation-saas-dev
python -m pytest tests/test_all_integrations.py -v
```

This will discover and run tests for all integration plugins and report coverage for each.