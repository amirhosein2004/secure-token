# 🔐 Secure Token

[![PyPI version](https://badge.fury.io/py/secure-token.svg)](https://badge.fury.io/py/secure-token)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://static.pepy.tech/badge/secure-token)](https://pepy.tech/project/secure-token)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/amirhosein2004/secure-token)

A simple and secure token management library for Python applications. Generate, validate, and manage encrypted tokens with ease.

Perfect for **authentication**, **API security**, **session management**, and **microservices**.

## ✨ Features

- **🛡️ Secure**: Fernet encryption with PBKDF2 key derivation
- **⚡ Fast**: Stateless design, no database required
- **🎯 Simple**: Easy-to-use API with clear examples
- **🔧 Flexible**: Custom permissions and expiration times
- **📦 Lightweight**: Minimal dependencies

## 📋 Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Methods Guide](#-methods-guide)
- [Configuration](#-configuration)
- [Error Handling](#-error-handling)
- [Utility Functions](#-utility-functions)
- [Validators](#-validators)
- [Complete Example](#-complete-example)

## 🚀 Installation

```bash
pip install secure-token
```

## 💡 Quick Start

A simple example to get you started:

```python
from secure_token import SecureTokenManager

# 1. Create token manager
manager = SecureTokenManager()

# 2. Generate a token (simplest way)
token = manager.generate_token(user_id="user_123")

# 3. Validate the token
result = manager.validate_token(token)
print(f"User: {result['user_id']}")  # User: user_123
```

### Example with Permissions

```python
# Token with different permissions
token = manager.generate_token(
    user_id="john_doe",
    permissions=["read", "write"],
    expires_in_hours=24
)

# Check specific permission
try:
    manager.check_permission(token, "write")
    print("Access granted!")
except PermissionDeniedError:
    print("Access denied!")
```

## 📚 Methods Guide

### 1️⃣ **generate_token** - Create Token

Generates a secure encrypted token.

**Parameters:**
- `user_id` (required): User identifier
- `permissions` (optional): List of permissions
- `expires_in_hours` (optional): Expiration time in hours
- `additional_data` (optional): Additional data to store

**Simple Examples:**
```python
from secure_token import SecureTokenManager

manager = SecureTokenManager()

# Example 1: Simplest form
token = manager.generate_token(user_id="user_123")

# Example 2: With permissions
token = manager.generate_token(
    user_id="admin_456",
    permissions=["read", "write", "delete"]
)

# Example 3: Complete with all options
token = manager.generate_token(
    user_id="user_789",
    permissions=["admin"],
    expires_in_hours=48,  # 2 days
    additional_data={
        "role": "administrator",
        "department": "IT"
    }
)
```

---

### 2️⃣ **validate_token** - Validate Token

Validates a token and returns its information.

**Returns:**
- `valid`: Token validity status
- `user_id`: User identifier
- `permissions`: List of permissions
- `expires_at`: Expiration datetime
- `time_remaining`: Time remaining until expiration

**Simple Examples:**
```python
# Example 1: Simple validation
result = manager.validate_token(token)
if result['valid']:
    print(f"User: {result['user_id']}")

# Example 2: Get complete information
result = manager.validate_token(token)
user_id = result['user_id']
permissions = result['permissions']
time_left = result['time_remaining']
print(f"User {user_id} - Time left: {time_left}")

# Example 3: Error handling
from secure_token import TokenExpiredError, InvalidTokenError

try:
    result = manager.validate_token(token)
    print("Token is valid!")
except TokenExpiredError:
    print("Token has expired!")
except InvalidTokenError:
    print("Token is invalid!")
```

---

### 3️⃣ **check_permission** - Check Permission

Checks if a user has a specific permission.

**Parameters:**
- `token`: User's token
- `required_permission`: Required permission to check

**Simple Examples:**
```python
from secure_token import PermissionDeniedError

# Example 1: Simple check
try:
    manager.check_permission(token, "admin")
    print("User is admin!")
except PermissionDeniedError:
    print("User is not admin!")

# Example 2: Check multiple permissions
permissions_to_check = ["read", "write", "delete"]

for perm in permissions_to_check:
    try:
        manager.check_permission(token, perm)
        print(f"✓ Has {perm} access")
    except PermissionDeniedError:
        print(f"✗ No {perm} access")

# Example 3: Use in a function
def has_admin_access(token):
    try:
        return manager.check_permission(token, "admin")
    except:
        return False

if has_admin_access(token):
    print("Welcome to admin panel!")
```

---

### 4️⃣ **refresh_token** - Refresh Token

Creates a new token with the same information.

**Parameters:**
- `token`: Current token
- `new_expires_in_hours` (optional): New expiration time

**Simple Examples:**
```python
# Example 1: Simple refresh (24 hours default)
new_token = manager.refresh_token(old_token)

# Example 2: Refresh with custom time
new_token = manager.refresh_token(old_token, new_expires_in_hours=72)

# Example 3: Auto-refresh
def auto_refresh_if_needed(token):
    """Refresh if less than 2 hours remaining"""
    try:
        info = manager.get_token_info(token)
        remaining = info['time_remaining']
        
        # If less than 2 hours remaining
        if "1:" in remaining or "0:" in remaining:
            return manager.refresh_token(token)
        return token
    except:
        return None

refreshed = auto_refresh_if_needed(my_token)
```

---

### 5️⃣ **get_token_info** - Get Token Information

Returns complete token information.

**Returns:**
- `token_id`: Unique identifier
- `user_id`: User identifier
- `permissions`: List of permissions
- `time_remaining`: Time remaining until expiration
- And more...

**Simple Examples:**
```python
# Example 1: Get simple information
info = manager.get_token_info(token)
print(f"User: {info['user_id']}")
print(f"Time left: {info['time_remaining']}")

# Example 2: Display complete information
info = manager.get_token_info(token)
print(f"""
📋 Token Information:
- User: {info['user_id']}
- Permissions: {info['permissions']}
- Issued at: {info['issued_at']}
- Expires at: {info['expires_at']}
- Time remaining: {info['time_remaining']}
""")

# Example 3: Check token status
info = manager.get_token_info(token)
if info['valid']:
    print("✓ Token is active")
    print(f"⏱ {info['time_remaining']} remaining")
else:
    print("✗ Token is inactive")
```

---

### 6️⃣ **export_config** - Export Configuration

Returns encryption configuration (for backup purposes).

**Simple Examples:**
```python
# Get configuration
config = manager.export_config()
print(f"Algorithm: {config['algorithm']}")
print(f"Version: {config['version']}")

# Save for backup
import json

config = manager.export_config()
with open('backup_config.json', 'w') as f:
    json.dump(config, f)
```

## 🔧 Configuration

### Configuration Methods

**1️⃣ Simple Method (Default):**
```python
from secure_token import SecureTokenManager

# Automatic settings
manager = SecureTokenManager()
```

**2️⃣ With Environment Variables:**
```python
import os
from secure_token import SecureTokenManager

# Set variables
os.environ['SECRET_KEY'] = 'MySecretKey@123'
os.environ['DEFAULT_EXPIRATION_HOURS'] = '12'

manager = SecureTokenManager()
```

**3️⃣ With .env File:**
```bash
# Create .env file:
SECRET_KEY=MySecretKey@123
DEFAULT_EXPIRATION_HOURS=12
```

```python
from dotenv import load_dotenv
from secure_token import SecureTokenManager

load_dotenv()
manager = SecureTokenManager()
```

**4️⃣ With Custom Settings:**
```python
from secure_token import SecureTokenManager, Settings

settings = Settings(
    SECRET_KEY="MyCustomKey@456!",
    DEFAULT_EXPIRATION_HOURS=48
)

manager = SecureTokenManager(settings_instance=settings)
```

> **🔒 Security Note:** `Settings` automatically validates all parameters during initialization. 
> If you provide invalid SECRET_KEY, SALT, or expiration time, it will raise an error immediately.

### Settings Validation Requirements

**SECRET_KEY Requirements:**
- Minimum 16 characters
- Contains uppercase and lowercase letters
- At least one number
- At least one special character (@$!%*?&#)

**Valid SECRET_KEY Examples:**
```python
# ✓ Valid
"MyPassword@123"
"SecureApp#2025"
"StrongKey!Abc123"

# ✗ Invalid - Will raise TokenError
"weak"           # Too short
"nocapitals123"  # No uppercase letters
"NoNumbers!"     # No numbers
"NoSpecial123"   # No special characters
```

**Example with Error Handling:**
```python
from secure_token import Settings, SecureTokenManager, TokenError

try:
    settings = Settings(
        SECRET_KEY="weak",  # Too weak!
        DEFAULT_EXPIRATION_HOURS=24
    )
except TokenError as e:
    print(f"Settings validation error: {e}")

# Valid settings
settings = Settings(
    SECRET_KEY="MyStrongPassword@123",
    DEFAULT_EXPIRATION_HOURS=24
)
manager = SecureTokenManager(settings_instance=settings)
```


## ⚠️ Error Handling

The library provides 4 different error types:

**Error Types:**
- `TokenError` - Base exception
- `TokenExpiredError` - Token has expired
- `InvalidTokenError` - Token is invalid
- `PermissionDeniedError` - Permission denied

**Simple Examples:**
```python
from secure_token import (
    SecureTokenManager,
    TokenExpiredError,
    InvalidTokenError,
    PermissionDeniedError
)

manager = SecureTokenManager()

# Example 1: Simple handling
try:
    result = manager.validate_token(token)
    print("Token is valid!")
except TokenExpiredError:
    print("⏱ Token expired - please login again")
except InvalidTokenError:
    print("❌ Token is invalid")
except Exception as e:
    print(f"Error: {e}")

# Example 2: Check permission
try:
    manager.check_permission(token, "admin")
    print("✓ Has admin access")
except PermissionDeniedError:
    print("✗ No admin access")
except TokenExpiredError:
    print("⏱ Token expired")

# Example 3: Safe validation function
def safe_validate(token):
    """Safe validation"""
    try:
        return manager.validate_token(token)
    except TokenExpiredError:
        return {"valid": False, "error": "expired"}
    except InvalidTokenError:
        return {"valid": False, "error": "invalid"}
    except Exception:
        return {"valid": False, "error": "unknown"}
```

---

## 🎨 Complete Example

A simple authentication system:

```python
from secure_token import SecureTokenManager

class AuthSystem:
    """Simple authentication system"""
    
    def __init__(self):
        self.manager = SecureTokenManager()
    
    def login(self, username, permissions=None):
        """Login user and create token"""
        token = self.manager.generate_token(
            user_id=username,
            permissions=permissions or ["read"],
            expires_in_hours=24
        )
        print(f"✓ {username} logged in")
        return token
    
    def check_access(self, token, permission):
        """Check access permission"""
        try:
            self.manager.check_permission(token, permission)
            return True
        except:
            return False
    
    def get_user(self, token):
        """Get user information"""
        try:
            result = self.manager.validate_token(token)
            return result['user_id']
        except:
            return None

# Usage
auth = AuthSystem()

# Login regular user
user_token = auth.login("john", ["read", "write"])

# Login admin
admin_token = auth.login("admin", ["read", "write", "admin"])

# Check access
if auth.check_access(user_token, "write"):
    print("✓ User can write")

if auth.check_access(user_token, "admin"):
    print("✓ User is admin")
else:
    print("✗ User is not admin")

# Get username
username = auth.get_user(user_token)
print(f"Username: {username}")
```

## 🔧 Utility Functions

### **generate_secret_key** - Generate Secret Key

Generates a secure random secret key.

**Examples:**
```python
from secure_token import generate_secret_key

# Generate 32-character key
key = generate_secret_key(32)
print(key)  # Example: "kJ8mN3qR7sT2vW9yB4xD6zA1cF5gH0iL"

# Generate 16-character key
short_key = generate_secret_key(16)

# Use in settings
from secure_token import Settings, SecureTokenManager

settings = Settings(
    SECRET_KEY=generate_secret_key(32),
    DEFAULT_EXPIRATION_HOURS=24
)
manager = SecureTokenManager(settings_instance=settings)
```

---

### **generate_salt** - Generate Salt

Generates random salt for enhanced security.

**Examples:**
```python
from secure_token import generate_salt

# Generate 32-byte salt
salt = generate_salt(32)
print(len(salt))  # 32

# Generate 16-byte salt
small_salt = generate_salt(16)

# Use in settings
from secure_token import Settings, SecureTokenManager

settings = Settings(
    SECRET_KEY="MySecretKey@123",
    SALT=generate_salt(32),
    DEFAULT_EXPIRATION_HOURS=24
)
manager = SecureTokenManager(settings_instance=settings)
```

---

## ✅ Validators

### **validate_permissions** - Validate Permissions

Validates a list of permissions.

**Examples:**
```python
from secure_token import validate_permissions

# Example 1: Valid list
try:
    validate_permissions(["read", "write", "admin"])
    print("✓ Permissions are valid")
except Exception as e:
    print(f"✗ Error: {e}")

# Example 2: Invalid list
try:
    validate_permissions(["x"])  # Too short!
except Exception as e:
    print(f"Error: {e}")  # Length must be between 2 and 30

# Example 3: Use in a function
def add_permission(permissions, new_perm):
    """Add new permission"""
    test_list = permissions + [new_perm]
    try:
        validate_permissions(test_list)
        return test_list
    except:
        return permissions  # Return previous list
```

---

### **validate_expires_hours** - Validate Expiration Time

Validates expiration time (must be between 0 and 8760 hours).

**Examples:**
```python
from secure_token import validate_expires_hours

# Example 1: Valid times
try:
    validate_expires_hours(24)  # ✓ 24 hours
    validate_expires_hours(168)  # ✓ 1 week
    validate_expires_hours(720)  # ✓ 1 month
    print("✓ Times are valid")
except Exception as e:
    print(f"✗ Error: {e}")

# Example 2: Invalid time
try:
    validate_expires_hours(10000)  # Too much!
except Exception as e:
    print(f"Error: {e}")  # Must be less than 8760

# Example 3: Use in a function
def safe_expiration(hours):
    """Safe expiration setting"""
    try:
        validate_expires_hours(hours)
        return hours
    except:
        return 24  # Default 24 hours
```

---

## 📚 Documentation

### 📖 Complete Documentation

For more information:

- **📋 [API Reference](docs/api-reference.md)** - Complete API reference
- **🎓 [Tutorial Guide](docs/tutorial-guide.md)** - Step-by-step guide
- **🔧 [Advanced Examples](docs/advanced-examples.md)** - Advanced examples with Flask and Django
- **⚙️ [Development Setup](docs/development-setup.md)** - Development environment setup
- **🧪 [Testing Guide](docs/testing-guide.md)** - Testing guide

### 🌐 Online Documentation

> **[📖 Full Online Documentation](https://secure-token.readthedocs.io/en/)**

---

## 🤝 Contributing

We welcome contributions!

Please see our [Contributing Guide](CONTRIBUTING.md) for more information.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🔗 Links

- **📦 PyPI**: [pypi.org/project/secure-token](https://pypi.org/project/secure-token/)
- **💻 GitHub**: [github.com/amirhosein2004/secure-token](https://github.com/amirhosein2004/secure-token)
- **📖 Docs**: [secure-token.readthedocs.io](https://secure-token.readthedocs.io/en/)
- **🐛 Issues**: [Report Bug](https://github.com/amirhosein2004/secure-token/issues)

---

## 👨‍💻 Author

**Made with ❤️ by [AmirHossein Babaee](https://github.com/amirhosein2004)**

*Secure Token - Because your application's security matters*

---

## 📊 Methods Summary

| Method | Purpose | Example |
|--------|---------|---------|
| `generate_token` | Create token | `manager.generate_token("user_123")` |
| `validate_token` | Validate token | `manager.validate_token(token)` |
| `check_permission` | Check permission | `manager.check_permission(token, "admin")` |
| `refresh_token` | Refresh token | `manager.refresh_token(token)` |
| `get_token_info` | Get token info | `manager.get_token_info(token)` |
| `export_config` | Export config | `manager.export_config()` |
| `generate_secret_key` | Generate key | `generate_secret_key(32)` |
| `generate_salt` | Generate salt | `generate_salt(32)` |

---

**⭐ If you find this project useful, don't forget to give it a star!**
