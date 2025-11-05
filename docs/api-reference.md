# 📋 API Reference

Complete API documentation for Secure Token library.

## Table of Contents

- [SecureTokenManager](#securetokenmanager)
- [Settings](#settings)
- [Exceptions](#exceptions)
- [Utility Functions](#utility-functions)
- [Validators](#validators)

## SecureTokenManager

The main class for token management operations.

### Constructor

```python
SecureTokenManager(settings_instance: Optional[Settings] = None)
```

**Parameters:**
- `settings_instance` (Optional[Settings]): Custom settings instance. If None, uses default settings.

**Example:**
```python
from secure_token import SecureTokenManager, Settings

# Default settings
manager = SecureTokenManager()

# Custom settings
settings = Settings(SECRET_KEY="my-secret", DEFAULT_EXPIRATION_HOURS=12)
manager = SecureTokenManager(settings_instance=settings)
```

### Methods

#### generate_token()

Generate a new secure encrypted token.

```python
generate_token(
    user_id: str,
    permissions: Optional[List[str]] = None,
    expires_in_hours: Optional[int] = None,
    additional_data: Optional[Dict[str, Any]] = None
) -> str
```

**Parameters:**
- `user_id` (str): Unique user identifier (required)
- `permissions` (Optional[List[str]]): List of user permissions
- `expires_in_hours` (Optional[int]): Token expiration time in hours
- `additional_data` (Optional[Dict[str, Any]]): Additional data to store in token

**Returns:**
- `str`: Base64-encoded encrypted token

**Raises:**
- `TokenError`: Error during token generation
- `ValueError`: Invalid input parameters

**Example:**
```python
# Basic token
token = manager.generate_token("user123")

# Advanced token
token = manager.generate_token(
    user_id="admin_user",
    permissions=["read", "write", "admin"],
    expires_in_hours=24,
    additional_data={"role": "administrator", "department": "IT"}
)
```

#### validate_token()

Validate and decrypt a token.

```python
validate_token(token: str) -> Dict[str, Any]
```

**Parameters:**
- `token` (str): Token to validate

**Returns:**
- `Dict[str, Any]`: Validation result containing:
  - `valid` (bool): Whether token is valid
  - `user_id` (str): User ID from token
  - `permissions` (List[str]): User permissions
  - `expires_at` (datetime): Token expiration time
  - `issued_at` (datetime): Token issue time
  - `additional_data` (Dict): Additional data from token
  - `time_remaining` (str): Time until expiration

**Raises:**
- `InvalidTokenError`: Token format is invalid
- `TokenExpiredError`: Token has expired
- `TokenError`: Other token-related errors

**Example:**
```python
try:
    result = manager.validate_token(token)
    user_id = result['user_id']
    permissions = result['permissions']
except TokenExpiredError:
    pass
except InvalidTokenError:
    pass
```

#### refresh_token()

Create a new token with extended expiration time.

```python
refresh_token(
    token: str,
    new_expires_in_hours: Optional[int] = None
) -> str
```

**Parameters:**
- `token` (str): Current valid token
- `new_expires_in_hours` (Optional[int]): New expiration time in hours

**Returns:**
- `str`: New refreshed token

**Raises:**
- `InvalidTokenError`: Token format is invalid
- `TokenExpiredError`: Token has expired
- `TokenError`: Error during refresh

**Example:**
```python
# Refresh with default expiration
new_token = manager.refresh_token(old_token)

# Refresh with custom expiration
new_token = manager.refresh_token(old_token, new_expires_in_hours=48)
```

#### get_token_info()

Get comprehensive information about a token.

```python
get_token_info(token: str) -> Dict[str, Any]
```

**Parameters:**
- `token` (str): Token to analyze

**Returns:**
- `Dict[str, Any]`: Token information containing:
  - `valid` (bool): Token validity
  - `token_id` (str): Unique token identifier
  - `user_id` (str): User ID
  - `permissions` (List[str]): User permissions
  - `issued_at` (str): Issue timestamp
  - `expires_at` (str): Expiration timestamp
  - `additional_data` (Dict): Additional data
  - `time_remaining` (str): Time until expiration
  - `is_revoked` (bool): Revocation status (always False in stateless mode)

**Raises:**
- `InvalidTokenError`: Token format is invalid
- `TokenExpiredError`: Token has expired
- `TokenError`: Error getting token info

**Example:**
```python
info = manager.get_token_info(token)
token_id = info['token_id']
user_id = info['user_id']
time_remaining = info['time_remaining']
# Use token information as needed
```

#### check_permission()

Check if token has a specific permission.

```python
check_permission(token: str, required_permission: str) -> bool
```

**Parameters:**
- `token` (str): Token to check
- `required_permission` (str): Permission to verify

**Returns:**
- `bool`: True if permission exists

**Raises:**
- `InvalidTokenError`: Token is invalid
- `TokenExpiredError`: Token has expired
- `PermissionDeniedError`: Permission not granted
- `TokenError`: Other token errors

**Example:**
```python
try:
    manager.check_permission(token, "admin")
    # Grant admin access
except PermissionDeniedError:
    # Handle access denied
    pass
```

#### export_config()

Export current configuration for backup purposes.

```python
export_config() -> Dict[str, str]
```

**Returns:**
- `Dict[str, str]`: Configuration data containing:
  - `secret_key_hash` (str): Hashed secret key (first 16 bytes)
  - `salt` (str): Base64-encoded salt
  - `version` (str): Library version
  - `algorithm` (str): Encryption algorithm used

**Example:**
```python
config = manager.export_config()
algorithm = config['algorithm']
version = config['version']
# Use configuration data as needed
```

## Settings

Configuration class for SecureTokenManager.

### Constructor

```python
Settings(
    SECRET_KEY: Optional[str] = None,
    DEFAULT_EXPIRATION_HOURS: int = 24,
    SALT: Optional[bytes] = None
)
```

**Parameters:**
- `SECRET_KEY` (Optional[str]): Secret key for encryption (auto-generated if None)
- `DEFAULT_EXPIRATION_HOURS` (int): Default token expiration time
- `SALT` (Optional[bytes]): Salt for key derivation (auto-generated if None)

**Example:**
```python
from secure_token import Settings

settings = Settings(
    SECRET_KEY="my-super-secret-key",
    DEFAULT_EXPIRATION_HOURS=12,
    SALT=b"my-custom-salt-32-bytes-long!!"
)
```

**Validation:**
`Settings` automatically validates all parameters during initialization. If you provide invalid values, it will raise a `TokenError`.

**Example with validation:**
```python
from secure_token import Settings, TokenError

try:
    settings = Settings(SECRET_KEY="weak")  # Too weak!
except TokenError as e:
    print(f"Validation error: {e}")

# Valid settings
settings = Settings(SECRET_KEY="MyStrongPassword@123")
```

## Exceptions

Custom exception classes for error handling.

### TokenError

Base exception for all token-related errors.

```python
class TokenError(Exception):
    """Base exception for token operations"""
```

### TokenExpiredError

Raised when a token has expired.

```python
class TokenExpiredError(TokenError):
    """Token has expired"""
```

### InvalidTokenError

Raised when token format is invalid.

```python
class InvalidTokenError(TokenError):
    """Token format is invalid"""
```

### PermissionDeniedError

Raised when required permission is not granted.

```python
class PermissionDeniedError(TokenError):
    """Permission denied"""
```

**Example Usage:**
```python
from secure_token import (
    TokenError, TokenExpiredError,
    InvalidTokenError, PermissionDeniedError
)

try:
    result = manager.validate_token(token)
    # Process successful validation
except TokenExpiredError:
    # Handle expired token - redirect to login
    pass
except InvalidTokenError:
    # Handle invalid token - authentication failed
    pass
except PermissionDeniedError:
    # Handle permission issues - access denied
    pass
except TokenError as e:
    # Handle other token errors
    pass
```

## Utility Functions

Helper functions for token operations.

### generate_secret_key()

Generate a cryptographically secure secret key.

```python
generate_secret_key(length: int = 32) -> str
```

**Parameters:**
- `length` (int): Key length in bytes (default: 32)

**Returns:**
- `str`: URL-safe base64-encoded secret key

**Example:**
```python
from secure_token import generate_secret_key

secret = generate_secret_key(32)
# Use the generated secret key securely
```

### generate_salt()

Generate a cryptographically secure salt.

```python
generate_salt(length: int = 32) -> bytes
```

**Parameters:**
- `length` (int): Salt length in bytes (default: 32)

**Returns:**
- `bytes`: Random salt bytes

**Example:**
```python
from secure_token import generate_salt

salt = generate_salt(32)
# Use the generated salt for key derivation
```

## Validators

Input validation functions.

### validate_user_id()

Validate user ID format.

```python
validate_user_id(user_id: str) -> None
```

**Parameters:**
- `user_id` (str): User ID to validate

**Raises:**
- `ValueError`: If user ID is invalid

**Example:**
```python
from secure_token import validate_user_id

try:
    validate_user_id("user123")
    # User ID is valid
except ValueError as e:
    # Handle invalid user ID
    pass
```

### validate_permissions()

Validate permissions list format.

```python
validate_permissions(permissions: List[str]) -> None
```

**Parameters:**
- `permissions` (List[str]): Permissions to validate

**Raises:**
- `ValueError`: If permissions are invalid

**Example:**
```python
from secure_token import validate_permissions

try:
    validate_permissions(["read", "write", "admin"])
    # Permissions are valid
except ValueError as e:
    # Handle invalid permissions
    pass
```

### validate_expires_hours()

Validate expiration hours value.

```python
validate_expires_hours(hours: int) -> None
```

**Parameters:**
- `hours` (int): Hours to validate

**Raises:**
- `ValueError`: If hours value is invalid

**Example:**
```python
from secure_token import validate_expires_hours

try:
    validate_expires_hours(24)
    # Expiration time is valid
except ValueError as e:
    # Handle invalid expiration time
    pass
```

## Performance Characteristics

- **Token Generation**: ~15,000 tokens/second
- **Token Validation**: ~21,000 validations/second
- **Memory Usage**: Minimal (stateless design)
- **Thread Safety**: Full thread-safe operations
- **Encryption**: Fernet with PBKDF2 (100,000 iterations)

## Security Notes

1. **Secret Key**: Must be kept secure and never exposed
2. **Salt**: Should be unique per application instance
3. **Token Storage**: Tokens should be transmitted over HTTPS only
4. **Expiration**: Set appropriate expiration times based on security needs
5. **Permissions**: Use principle of least privilege

---

**Next:** [Tutorial Guide](tutorial-guide.md) | **Back to:** [Main README](../README.md)
