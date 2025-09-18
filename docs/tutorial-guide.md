# 🎓 Tutorial Guide

Step-by-step beginner's guide to using Secure Token library.

## Table of Contents

1. [Installation](#1-installation)
2. [Basic Setup](#2-basic-setup)
3. [Your First Token](#3-your-first-token)
4. [Adding Permissions](#4-adding-permissions)
5. [Token Validation](#5-token-validation)
6. [Error Handling](#6-error-handling)
7. [Token Refresh](#7-token-refresh)
8. [Advanced Features](#8-advanced-features)
9. [Production Setup](#9-production-setup)
10. [Common Patterns](#10-common-patterns)

## 1. Installation

First, install the Secure Token library:

```bash
pip install secure-token
```

For development with additional tools:
```bash
pip install secure-token[dev]
```

## 2. Basic Setup

Create your first Python file and import the library:

```python
# app.py
from secure_token import SecureTokenManager

# Initialize the token manager
manager = SecureTokenManager()

# Token manager is now ready for use
```

Run the file:
```bash
python app.py
```

**Result:**
```
Token manager initialized and ready for use
```

## 3. Your First Token

Let's generate your first secure token:

```python
# app.py
from secure_token import SecureTokenManager

# Initialize manager
manager = SecureTokenManager()

# Generate a basic token
token = manager.generate_token(user_id="tutorial_user")

# Token is now ready for use
token_length = len(token)
```

**Result:**
```
Token generated successfully
Token length: 156 characters
```

### Understanding the Token

- Tokens are **encrypted** and **base64-encoded**
- They contain user information, permissions, and expiration time
- They are **stateless** - no database storage required
- Default expiration is **24 hours**

## 4. Adding Permissions

Tokens can include user permissions for access control:

```python
# app.py
from secure_token import SecureTokenManager

manager = SecureTokenManager()

# Generate token with permissions
user_token = manager.generate_token(
    user_id="regular_user",
    permissions=["read", "write"]
)

admin_token = manager.generate_token(
    user_id="admin_user",
    permissions=["read", "write", "admin", "delete"]
)

# Tokens are now ready for use
# user_token has read/write permissions
# admin_token has full permissions
```

### Permission Examples

Common permission patterns:

```python
# Different user roles
guest_permissions = ["read"]
user_permissions = ["read", "write"]
moderator_permissions = ["read", "write", "moderate"]
admin_permissions = ["read", "write", "moderate", "admin", "delete"]

# API-specific permissions
api_permissions = ["api:read", "api:write", "api:admin"]

# Resource-specific permissions
file_permissions = ["files:read", "files:write", "files:delete"]
```

## 5. Token Validation

Learn how to validate and extract information from tokens:

```python
# app.py
from secure_token import SecureTokenManager, TokenExpiredError, InvalidTokenError

manager = SecureTokenManager()

# Generate a token
token = manager.generate_token(
    user_id="test_user",
    permissions=["read", "write"],
    expires_in_hours=2
)

# Validate the token
try:
    result = manager.validate_token(token)

    # Access validation results
    user_id = result['user_id']
    permissions = result['permissions']
    expires_at = result['expires_at']
    time_remaining = result['time_remaining']
    is_valid = result['valid']

except TokenExpiredError:
    # Handle expired token
    pass
except InvalidTokenError:
    # Handle invalid token
    pass
```

**Result:**
```
Token validation successful
User ID: test_user
Permissions: ['read', 'write']
Expires at: 2025-01-07 14:30:00
Time remaining: 1:59:45
Status: Valid
```

## 6. Error Handling

Proper error handling is crucial for robust applications:

```python
# app.py
from secure_token import (
    SecureTokenManager,
    TokenExpiredError,
    InvalidTokenError,
    PermissionDeniedError,
    TokenError
)

manager = SecureTokenManager()

def safe_token_validation(token):
    """Safely validate a token with comprehensive error handling"""
    try:
        result = manager.validate_token(token)
        return {
            "success": True,
            "data": result,
            "message": "Token validated successfully"
        }

    except TokenExpiredError:
        return {
            "success": False,
            "error": "expired",
            "message": "Token has expired. Please login again."
        }

    except InvalidTokenError:
        return {
            "success": False,
            "error": "invalid",
            "message": "Invalid token format. Authentication failed."
        }

    except TokenError as e:
        return {
            "success": False,
            "error": "token_error",
            "message": f"Token error: {str(e)}"
        }

    except Exception as e:
        return {
            "success": False,
            "error": "unknown",
            "message": f"Unexpected error: {str(e)}"
        }

# Test the function
token = manager.generate_token("test_user")
result = safe_token_validation(token)

if result["success"]:
    # Handle successful validation
    user_id = result['data']['user_id']
    # Process authenticated user
else:
    # Handle validation failure
    error_message = result['message']
    # Handle error appropriately
```

## 7. Token Refresh

Learn how to refresh tokens to extend their lifetime:

```python
# app.py
from secure_token import SecureTokenManager
import time

manager = SecureTokenManager()

# Generate a short-lived token (1 hour)
original_token = manager.generate_token(
    user_id="refresh_user",
    permissions=["read", "write"],
    expires_in_hours=1
)

# Original token created (expires in 1 hour)

# Get token info
info = manager.get_token_info(original_token)
original_expiration = info['expires_at']

# Refresh the token with new expiration (24 hours)
refreshed_token = manager.refresh_token(
    token=original_token,
    new_expires_in_hours=24
)

# Token refreshed successfully

# Check new expiration
new_info = manager.get_token_info(refreshed_token)
new_expiration = new_info['expires_at']
user_id = new_info['user_id']  # User ID preserved
permissions = new_info['permissions']  # Permissions preserved
```

### Automatic Refresh Pattern

```python
def auto_refresh_token(token, threshold_hours=2):
    """Automatically refresh token if it expires soon"""
    info = manager.get_token_info(token)
    time_remaining = info['time_remaining']

    # Parse remaining time (format: "X:XX:XX")
    hours_remaining = int(time_remaining.split(':')[0])

    if hours_remaining < threshold_hours:
        # Token expires soon, refreshing
        return manager.refresh_token(token, new_expires_in_hours=24)

    return token
```

## 8. Advanced Features

### Custom Token Data

Store additional information in tokens:

```python
# app.py
from secure_token import SecureTokenManager
import datetime

manager = SecureTokenManager()

# Token with custom data
token = manager.generate_token(
    user_id="advanced_user",
    permissions=["read", "write"],
    expires_in_hours=12,
    additional_data={
        "role": "developer",
        "department": "engineering",
        "login_time": datetime.datetime.now().isoformat(),
        "login_ip": "192.168.1.100",
        "session_id": "sess_abc123xyz",
        "preferences": {
            "theme": "dark",
            "language": "en"
        }
    }
)

# Extract custom data
result = manager.validate_token(token)
custom_data = result['additional_data']

# Access custom data from token
role = custom_data['role']
department = custom_data['department']
login_ip = custom_data['login_ip']
preferences = custom_data['preferences']
```

### Permission Checking

```python
# app.py
from secure_token import SecureTokenManager, PermissionDeniedError

manager = SecureTokenManager()

# Create tokens with different permissions
admin_token = manager.generate_token("admin", ["read", "write", "admin"])
user_token = manager.generate_token("user", ["read", "write"])

def check_access(token, required_permission):
    """Check if token has required permission"""
    try:
        manager.check_permission(token, required_permission)
        return True
    except PermissionDeniedError:
        return False

# Test permissions
admin_has_admin = check_access(admin_token, 'admin')
user_has_admin = check_access(user_token, 'admin')
user_has_read = check_access(user_token, 'read')
```

## 9. Production Setup

### Environment Variables

Create a `.env` file for production:

```bash
# .env
SECRET_KEY=your-super-secure-secret-key-change-this-in-production
DEFAULT_EXPIRATION_HOURS=8
SALT=your-custom-salt-32-bytes-long!!
```

### Production Code

```python
# production_app.py
import os
from dotenv import load_dotenv
from secure_token import SecureTokenManager, Settings

# Load environment variables
load_dotenv()

def create_production_manager():
    """Create token manager with production settings"""

    # Validate required environment variables
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key:
        raise ValueError("SECRET_KEY environment variable is required")

    # Create settings
    settings = Settings(
        SECRET_KEY=secret_key,
        DEFAULT_EXPIRATION_HOURS=int(os.getenv('DEFAULT_EXPIRATION_HOURS', 8)),
        SALT=os.getenv('SALT', 'default-salt-change-this!!').encode()
    )

    return SecureTokenManager(settings_instance=settings)

# Initialize for production
try:
    manager = create_production_manager()
    # Production token manager initialized successfully
except ValueError as e:
    # Handle configuration error
    pass
```

### Security Best Practices

```python
# security_utils.py
import secrets
import os

def generate_production_secret():
    """Generate a secure secret key for production"""
    return secrets.token_urlsafe(32)

def generate_production_salt():
    """Generate a secure salt for production"""
    return secrets.token_bytes(32)

def validate_production_config():
    """Validate production configuration"""
    checks = []

    # Check secret key
    secret = os.getenv('SECRET_KEY')
    if not secret:
        checks.append("SECRET_KEY not set")
    elif len(secret) < 32:
        checks.append("SECRET_KEY should be at least 32 characters")
    else:
        checks.append("SECRET_KEY configured")

    # Check expiration
    expiration = os.getenv('DEFAULT_EXPIRATION_HOURS')
    if expiration and int(expiration) > 24:
        checks.append("Consider shorter expiration time for production")
    else:
        checks.append("Expiration time appropriate")

    return checks

# Run validation
if __name__ == "__main__":
    # Production Security Check
    checks = validate_production_config()
    # Process security check results
```

## 10. Common Patterns

### Web Application Integration

```python
# web_auth.py
from secure_token import SecureTokenManager
from flask import Flask, request, jsonify

app = Flask(__name__)
manager = SecureTokenManager()

class AuthMiddleware:
    def __init__(self, token_manager):
        self.manager = token_manager

    def require_auth(self, required_permissions=None):
        """Decorator for routes requiring authentication"""
        def decorator(f):
            def wrapper(*args, **kwargs):
                # Get token from header
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({"error": "Missing or invalid token"}), 401

                token = auth_header.split(' ')[1]

                try:
                    # Validate token
                    result = self.manager.validate_token(token)

                    # Check permissions if required
                    if required_permissions:
                        for permission in required_permissions:
                            self.manager.check_permission(token, permission)

                    # Add user info to request context
                    request.user = result
                    return f(*args, **kwargs)

                except Exception as e:
                    return jsonify({"error": str(e)}), 403

            wrapper.__name__ = f.__name__
            return wrapper
        return decorator

# Initialize middleware
auth = AuthMiddleware(manager)

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint"""
    data = request.json
    username = data.get('username')

    # In real app, validate credentials here
    if username:
        token = manager.generate_token(
            user_id=username,
            permissions=["read", "write"],
            expires_in_hours=24
        )
        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"}), 400

@app.route('/profile')
@auth.require_auth()
def profile():
    """Protected route - requires valid token"""
    return jsonify({
        "user_id": request.user['user_id'],
        "permissions": request.user['permissions']
    })

@app.route('/admin')
@auth.require_auth(required_permissions=['admin'])
def admin():
    """Admin route - requires admin permission"""
    return jsonify({"message": "Admin access granted"})

if __name__ == '__main__':
    app.run(debug=True)
```

### Database Integration

```python
# database_integration.py
from secure_token import SecureTokenManager
import sqlite3
from datetime import datetime

manager = SecureTokenManager()

class UserSession:
    def __init__(self, db_path="sessions.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        conn.commit()
        conn.close()

    def create_session(self, user_id, permissions=None):
        """Create new user session"""
        token = manager.generate_token(
            user_id=user_id,
            permissions=permissions or ["read"],
            expires_in_hours=24
        )

        # Store session info (hash token for security)
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT INTO user_sessions (user_id, token_hash)
            VALUES (?, ?)
        ''', (user_id, token_hash))
        conn.commit()
        conn.close()

        return token

    def validate_session(self, token):
        """Validate session and update last_used"""
        try:
            result = manager.validate_token(token)

            # Update last used time
            import hashlib
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                UPDATE user_sessions
                SET last_used = CURRENT_TIMESTAMP
                WHERE token_hash = ? AND is_active = TRUE
            ''', (token_hash,))
            conn.commit()
            conn.close()

            return result
        except Exception as e:
            raise e

# Usage example
session_manager = UserSession()

# Create session
token = session_manager.create_session("user123", ["read", "write"])
print(f"✅ Session created: {token[:50]}...")

# Validate session
try:
    result = session_manager.validate_session(token)
    print(f"✅ Session valid for user: {result['user_id']}")
except Exception as e:
    print(f"❌ Session validation failed: {e}")
```

### Microservices Pattern

```python
# microservice_auth.py
from secure_token import SecureTokenManager
import requests
import json

class MicroserviceAuth:
    def __init__(self, service_name, shared_secret):
        self.service_name = service_name
        self.manager = SecureTokenManager()
        # In production, use shared secret from secure storage
        self.shared_secret = shared_secret

    def create_service_token(self, target_service, permissions=None):
        """Create token for service-to-service communication"""
        return self.manager.generate_token(
            user_id=f"service:{self.service_name}",
            permissions=permissions or ["service:read"],
            expires_in_hours=1,  # Short-lived for services
            additional_data={
                "service_name": self.service_name,
                "target_service": target_service,
                "token_type": "service"
            }
        )

    def validate_service_token(self, token):
        """Validate incoming service token"""
        try:
            result = self.manager.validate_token(token)

            # Verify it's a service token
            additional_data = result.get('additional_data', {})
            if additional_data.get('token_type') != 'service':
                raise ValueError("Not a service token")

            return result
        except Exception as e:
            raise e

    def make_authenticated_request(self, url, target_service, method='GET', data=None):
        """Make authenticated request to another service"""
        token = self.create_service_token(target_service, ["service:read", "service:write"])

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)

        return response

# Usage in different services
auth_service = MicroserviceAuth("user-service", "shared-secret-key")
payment_service = MicroserviceAuth("payment-service", "shared-secret-key")

# Service A calls Service B
response = auth_service.make_authenticated_request(
    url="http://payment-service/api/process",
    target_service="payment-service",
    method="POST",
    data={"amount": 100, "user_id": "user123"}
)
```

## Next Steps

1. **Read the [API Reference](api-reference.md)** for complete method documentation
2. **Check [Advanced Examples](advanced-examples.md)** for real-world implementations
3. **Review [Usage Guide](usage-guide.md)** for best practices
4. **Set up [Development Environment](development-setup.md)** for contributing

## Troubleshooting

### Common Issues

**Issue: "Token format is invalid"**
```python
# Solution: Check token encoding/decoding
token = manager.generate_token("user123")
print(f"Token type: {type(token)}")  # Should be <class 'str'>
print(f"Token length: {len(token)}")  # Should be > 100
```

**Issue: "Token has expired"**
```python
# Solution: Generate token with longer expiration
token = manager.generate_token("user123", expires_in_hours=48)
```

**Issue: "Permission denied"**
```python
# Solution: Check token permissions
result = manager.validate_token(token)
print(f"Token permissions: {result['permissions']}")
```

---

**Next:** [Advanced Examples](advanced-examples.md) | **Back to:** [Main README](../README.md)
