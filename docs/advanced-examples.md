# 🔧 Advanced Examples

Real-world implementation examples and advanced usage patterns.

## Table of Contents

- [Web Framework Integration](#web-framework-integration)
- [Django Integration](#django-integration)
- [Pure Python Applications](#pure-python-applications)
- [Microservices Authentication](#microservices-authentication)
- [API Gateway Pattern](#api-gateway-pattern)
- [Session Management](#session-management)
- [Multi-Tenant Applications](#multi-tenant-applications)
- [Performance Optimization](#performance-optimization)

## Web Framework Integration

### Flask Application

```python
from flask import Flask, request, jsonify, g
from secure_token import SecureTokenManager, TokenExpiredError, PermissionDeniedError
from functools import wraps

app = Flask(__name__)
manager = SecureTokenManager()

def token_required(permissions=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                return jsonify({'error': 'Token missing'}), 401

            try:
                result = manager.validate_token(token)
                g.current_user = result

                if permissions:
                    for perm in permissions:
                        manager.check_permission(token, perm)

                return f(*args, **kwargs)
            except (TokenExpiredError, PermissionDeniedError) as e:
                return jsonify({'error': str(e)}), 403

        return decorated
    return decorator

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    # Validate credentials (implement your logic)
    if validate_user(data.get('username'), data.get('password')):
        token = manager.generate_token(
            user_id=data['username'],
            permissions=get_user_permissions(data['username']),
            expires_in_hours=24
        )
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/profile')
@token_required()
def profile():
    return jsonify({
        'user_id': g.current_user['user_id'],
        'permissions': g.current_user['permissions']
    })

@app.route('/api/admin/users')
@token_required(permissions=['admin'])
def admin_users():
    return jsonify({'users': get_all_users()})
```

### FastAPI Implementation

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from secure_token import SecureTokenManager, TokenExpiredError, PermissionDeniedError
from typing import Optional, List

app = FastAPI()
manager = SecureTokenManager()

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Token missing")

    token = authorization.split(' ')[1]
    try:
        return manager.validate_token(token)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_permissions(required_perms: List[str]):
    def permission_checker(user: dict = Depends(get_current_user)):
        token = user.get('token')  # You'd need to store this
        for perm in required_perms:
            try:
                manager.check_permission(token, perm)
            except PermissionDeniedError:
                raise HTTPException(status_code=403, detail=f"Permission {perm} required")
        return user
    return permission_checker

@app.post("/login")
async def login(credentials: dict):
    if validate_credentials(credentials):
        token = manager.generate_token(
            user_id=credentials['username'],
            permissions=get_user_permissions(credentials['username'])
        )
        return {"token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/profile")
async def profile(user: dict = Depends(get_current_user)):
    return {"user_id": user['user_id'], "permissions": user['permissions']}
```

## Django Integration

### Django Middleware

```python
# middleware.py
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from secure_token import SecureTokenManager, TokenExpiredError, InvalidTokenError
import json

class TokenAuthenticationMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response
        self.manager = SecureTokenManager()
        super().__init__(get_response)

    def process_request(self, request):
        # Skip authentication for certain paths
        skip_paths = ['/login/', '/register/', '/health/', '/admin/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None

        # Get token from header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authentication required'}, status=401)

        token = auth_header[7:]  # Remove 'Bearer ' prefix

        try:
            result = self.manager.validate_token(token)
            request.user_info = result
            request.token = token
        except TokenExpiredError:
            return JsonResponse({'error': 'Token expired'}, status=401)
        except InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)
        except Exception:
            return JsonResponse({'error': 'Authentication failed'}, status=401)

        return None
```

### Django Views

```python
# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View
from secure_token import SecureTokenManager, PermissionDeniedError
import json

manager = SecureTokenManager()

def require_permissions(permissions):
    """Decorator to check user permissions"""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not hasattr(request, 'user_info'):
                return JsonResponse({'error': 'Authentication required'}, status=401)

            user_permissions = request.user_info.get('permissions', [])
            for perm in permissions:
                if perm not in user_permissions:
                    return JsonResponse({'error': f'Permission {perm} required'}, status=403)

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    """Login endpoint"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        # Validate credentials (implement your logic)
        if authenticate_user(username, password):
            token = manager.generate_token(
                user_id=username,
                permissions=get_user_permissions(username),
                expires_in_hours=24,
                additional_data={
                    'login_ip': get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
            return JsonResponse({'token': token, 'user_id': username})

        return JsonResponse({'error': 'Invalid credentials'}, status=401)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

def profile_view(request):
    """Get user profile"""
    return JsonResponse({
        'user_id': request.user_info['user_id'],
        'permissions': request.user_info['permissions'],
        'expires_at': request.user_info['expires_at']
    })

@require_permissions(['admin'])
def admin_view(request):
    """Admin-only endpoint"""
    return JsonResponse({'message': 'Admin access granted'})

class UserManagementView(View):
    """Class-based view with token authentication"""

    @method_decorator(require_permissions(['user:read']))
    def get(self, request):
        """List users"""
        return JsonResponse({'users': get_all_users()})

    @method_decorator(require_permissions(['user:create']))
    def post(self, request):
        """Create user"""
        data = json.loads(request.body)
        user = create_user(data)
        return JsonResponse({'user': user}, status=201)

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
```

### Django Settings Configuration

```python
# settings.py
import os
from pathlib import Path

# Secure Token Configuration
SECURE_TOKEN_CONFIG = {
    'SECRET_KEY': os.getenv('TOKEN_SECRET_KEY', 'your-secret-key-here'),
    'DEFAULT_EXPIRATION_HOURS': int(os.getenv('TOKEN_EXPIRATION_HOURS', 24)),
    'SALT': os.getenv('TOKEN_SALT', 'your-salt-here').encode()
}

# Add middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'myapp.middleware.TokenAuthenticationMiddleware',  # Add this
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

### Django URLs

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('api/login/', views.login_view, name='login'),
    path('api/profile/', views.profile_view, name='profile'),
    path('api/admin/', views.admin_view, name='admin'),
    path('api/users/', views.UserManagementView.as_view(), name='users'),
]
```

## Pure Python Applications

### Desktop Application with Tkinter

```python
# desktop_app.py
import tkinter as tk
from tkinter import messagebox, ttk
from secure_token import SecureTokenManager
import threading
import time

class SecureDesktopApp:
    def __init__(self):
        self.manager = SecureTokenManager()
        self.current_token = None
        self.current_user = None

        # Create main window
        self.root = tk.Tk()
        self.root.title("Secure Desktop Application")
        self.root.geometry("600x400")

        self.create_widgets()

    def create_widgets(self):
        """Create GUI widgets"""
        # Login frame
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(pady=20)

        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5)

        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5)

        self.login_btn = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # Main app frame (hidden initially)
        self.main_frame = ttk.Frame(self.root)

        self.status_label = ttk.Label(self.main_frame, text="Not logged in")
        self.status_label.pack(pady=10)

        self.user_info_text = tk.Text(self.main_frame, height=10, width=60)
        self.user_info_text.pack(pady=10)

        self.logout_btn = ttk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_btn.pack(pady=5)

        # Start token refresh thread
        self.start_token_refresh_thread()

    def login(self):
        """Handle user login"""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return

        # Simulate authentication (implement your logic)
        if self.authenticate_user(username, password):
            try:
                self.current_token = self.manager.generate_token(
                    user_id=username,
                    permissions=self.get_user_permissions(username),
                    expires_in_hours=8,  # Shorter for desktop apps
                    additional_data={
                        'app_type': 'desktop',
                        'login_time': time.time()
                    }
                )

                self.current_user = username
                self.show_main_app()

            except Exception as e:
                messagebox.showerror("Error", f"Login failed: {e}")
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def authenticate_user(self, username, password):
        """Simulate user authentication"""
        # In real app, check against database or API
        valid_users = {
            'admin': 'admin123',
            'user': 'user123'
        }
        return valid_users.get(username) == password

    def get_user_permissions(self, username):
        """Get user permissions"""
        if username == 'admin':
            return ['read', 'write', 'admin', 'delete']
        return ['read', 'write']

    def show_main_app(self):
        """Show main application interface"""
        self.login_frame.pack_forget()
        self.main_frame.pack(pady=20)

        self.update_user_info()

    def update_user_info(self):
        """Update user information display"""
        if self.current_token:
            try:
                info = self.manager.get_token_info(self.current_token)

                self.status_label.config(text=f"Logged in as: {self.current_user}")

                info_text = f"""
User ID: {info['user_id']}
Permissions: {', '.join(info['permissions'])}
Token ID: {info['token_id']}
Issued At: {info['issued_at']}
Expires At: {info['expires_at']}
Time Remaining: {info['time_remaining']}
Status: {'✅ Active' if info['valid'] else '❌ Invalid'}
                """.strip()

                self.user_info_text.delete(1.0, tk.END)
                self.user_info_text.insert(1.0, info_text)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to get token info: {e}")
                self.logout()

    def logout(self):
        """Handle user logout"""
        self.current_token = None
        self.current_user = None

        self.main_frame.pack_forget()
        self.login_frame.pack(pady=20)

        # Clear entries
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def start_token_refresh_thread(self):
        """Start background thread to refresh token"""
        def refresh_loop():
            while True:
                time.sleep(60)  # Check every minute
                if self.current_token:
                    try:
                        info = self.manager.get_token_info(self.current_token)
                        # Refresh if less than 1 hour remaining
                        remaining_seconds = self.parse_time_remaining(info['time_remaining'])

                        if remaining_seconds < 3600:  # Less than 1 hour
                            self.current_token = self.manager.refresh_token(
                                self.current_token,
                                new_expires_in_hours=8
                            )
                            # Update UI in main thread
                            self.root.after(0, self.update_user_info)

                    except Exception:
                        # Token expired or invalid, logout
                        self.root.after(0, self.logout)

        refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        refresh_thread.start()

    def parse_time_remaining(self, time_str):
        """Parse time remaining string to seconds"""
        try:
            parts = time_str.split(':')
            hours = int(parts[0])
            minutes = int(parts[1])
            seconds = int(parts[2])
            return hours * 3600 + minutes * 60 + seconds
        except:
            return 0

    def run(self):
        """Start the application"""
        self.root.mainloop()

# Usage
if __name__ == "__main__":
    app = SecureDesktopApp()
    app.run()
```

### Command Line Tool

```python
# cli_tool.py
import argparse
import getpass
import json
from secure_token import SecureTokenManager
import os

class SecureCLI:
    def __init__(self):
        self.manager = SecureTokenManager()
        self.token_file = os.path.expanduser('~/.secure_cli_token')

    def save_token(self, token):
        """Save token to file"""
        with open(self.token_file, 'w') as f:
            json.dump({'token': token}, f)
        os.chmod(self.token_file, 0o600)  # Secure permissions

    def load_token(self):
        """Load token from file"""
        try:
            with open(self.token_file, 'r') as f:
                data = json.load(f)
                return data.get('token')
        except FileNotFoundError:
            return None

    def remove_token(self):
        """Remove saved token"""
        try:
            os.remove(self.token_file)
        except FileNotFoundError:
            pass

    def login(self, username, password=None):
        """Login and save token"""
        if not password:
            password = getpass.getpass("Password: ")

        # Simulate authentication
        if self.authenticate_user(username, password):
            token = self.manager.generate_token(
                user_id=username,
                permissions=self.get_user_permissions(username),
                expires_in_hours=24,
                additional_data={'cli_login': True}
            )

            self.save_token(token)
            print(f"✅ Logged in as {username}")
            return True
        else:
            print("❌ Invalid credentials")
            return False

    def logout(self):
        """Logout and remove token"""
        self.remove_token()
        print("✅ Logged out successfully")

    def status(self):
        """Show current login status"""
        token = self.load_token()
        if not token:
            print("❌ Not logged in")
            return

        try:
            info = self.manager.get_token_info(token)
            print(f"✅ Logged in as: {info['user_id']}")
            print(f"🔑 Permissions: {', '.join(info['permissions'])}")
            print(f"⏰ Expires at: {info['expires_at']}")
            print(f"⏳ Time remaining: {info['time_remaining']}")
        except Exception as e:
            print(f"❌ Token invalid: {e}")
            self.remove_token()

    def execute_command(self, command, required_permission=None):
        """Execute command with authentication"""
        token = self.load_token()
        if not token:
            print("❌ Please login first: cli_tool.py login <username>")
            return False

        try:
            result = self.manager.validate_token(token)

            if required_permission:
                if required_permission not in result['permissions']:
                    print(f"❌ Permission '{required_permission}' required")
                    return False

            print(f"✅ Executing {command} as {result['user_id']}")
            # Execute your command logic here
            return True

        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            self.remove_token()
            return False

    def authenticate_user(self, username, password):
        """Simulate user authentication"""
        valid_users = {
            'admin': 'admin123',
            'user': 'user123'
        }
        return valid_users.get(username) == password

    def get_user_permissions(self, username):
        """Get user permissions"""
        if username == 'admin':
            return ['read', 'write', 'admin', 'delete']
        return ['read', 'write']

def main():
    cli = SecureCLI()
    parser = argparse.ArgumentParser(description='Secure CLI Tool')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Login command
    login_parser = subparsers.add_parser('login', help='Login to the system')
    login_parser.add_argument('username', help='Username')
    login_parser.add_argument('--password', help='Password (will prompt if not provided)')

    # Logout command
    subparsers.add_parser('logout', help='Logout from the system')

    # Status command
    subparsers.add_parser('status', help='Show login status')

    # Protected commands
    read_parser = subparsers.add_parser('read', help='Read data (requires read permission)')
    write_parser = subparsers.add_parser('write', help='Write data (requires write permission)')
    admin_parser = subparsers.add_parser('admin', help='Admin operations (requires admin permission)')

    args = parser.parse_args()

    if args.command == 'login':
        cli.login(args.username, args.password)
    elif args.command == 'logout':
        cli.logout()
    elif args.command == 'status':
        cli.status()
    elif args.command == 'read':
        cli.execute_command('read', 'read')
    elif args.command == 'write':
        cli.execute_command('write', 'write')
    elif args.command == 'admin':
        cli.execute_command('admin', 'admin')
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
```

## Microservices Authentication

### Service-to-Service Communication

```python
import requests
from secure_token import SecureTokenManager

class ServiceAuthenticator:
    def __init__(self, service_name: str, shared_secret: str):
        self.service_name = service_name
        self.manager = SecureTokenManager()

    def create_service_token(self, target_service: str) -> str:
        return self.manager.generate_token(
            user_id=f"service:{self.service_name}",
            permissions=[f"service:{target_service}"],
            expires_in_hours=1,
            additional_data={
                "service_type": "internal",
                "source_service": self.service_name,
                "target_service": target_service
            }
        )

    def make_authenticated_request(self, url: str, target_service: str, **kwargs):
        token = self.create_service_token(target_service)
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {token}'
        kwargs['headers'] = headers
        return requests.request(**kwargs)

# Usage in different services
user_service = ServiceAuthenticator("user-service", "shared-secret")
payment_service = ServiceAuthenticator("payment-service", "shared-secret")

# User service calls payment service
response = user_service.make_authenticated_request(
    url="http://payment-service/api/charge",
    target_service="payment-service",
    method="POST",
    json={"user_id": "123", "amount": 50.00}
)
```

## API Gateway Pattern

```python
from secure_token import SecureTokenManager
import httpx
import asyncio

class APIGateway:
    def __init__(self):
        self.manager = SecureTokenManager()
        self.services = {
            "user": "http://user-service:8001",
            "payment": "http://payment-service:8002",
            "notification": "http://notification-service:8003"
        }

    async def authenticate_request(self, token: str) -> dict:
        try:
            return self.manager.validate_token(token)
        except Exception as e:
            raise ValueError(f"Authentication failed: {e}")

    async def route_request(self, service: str, path: str, method: str,
                          headers: dict, data: dict = None):
        # Validate incoming token
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            raise ValueError("Missing or invalid authorization header")

        token = auth_header.split(' ')[1]
        user_info = await self.authenticate_request(token)

        # Create service token
        service_token = self.manager.generate_token(
            user_id=f"gateway:{user_info['user_id']}",
            permissions=user_info['permissions'],
            expires_in_hours=1,
            additional_data={
                "original_user": user_info['user_id'],
                "gateway_forwarded": True
            }
        )

        # Forward request to service
        service_url = self.services.get(service)
        if not service_url:
            raise ValueError(f"Unknown service: {service}")

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=f"{service_url}{path}",
                headers={'Authorization': f'Bearer {service_token}'},
                json=data
            )
            return response.json()

# Usage
gateway = APIGateway()

async def handle_request():
    result = await gateway.route_request(
        service="user",
        path="/api/profile",
        method="GET",
        headers={"Authorization": "Bearer user_token_here"}
    )
    return result
```

## Session Management

```python
import redis
import json
from datetime import datetime, timedelta
from secure_token import SecureTokenManager

class RedisSessionManager:
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.manager = SecureTokenManager()

    def create_session(self, user_id: str, permissions: list,
                      expires_in_hours: int = 24) -> str:
        # Generate token
        token = self.manager.generate_token(
            user_id=user_id,
            permissions=permissions,
            expires_in_hours=expires_in_hours
        )

        # Store session data in Redis
        session_data = {
            "user_id": user_id,
            "permissions": permissions,
            "created_at": datetime.now().isoformat(),
            "last_accessed": datetime.now().isoformat(),
            "token_hash": hash(token)  # Store hash for security
        }

        # Use token hash as Redis key
        redis_key = f"session:{hash(token)}"
        self.redis_client.setex(
            redis_key,
            timedelta(hours=expires_in_hours),
            json.dumps(session_data)
        )

        return token

    def validate_session(self, token: str) -> dict:
        # Validate token cryptographically
        token_data = self.manager.validate_token(token)

        # Check Redis for session data
        redis_key = f"session:{hash(token)}"
        session_data = self.redis_client.get(redis_key)

        if not session_data:
            raise ValueError("Session not found or expired")

        session_info = json.loads(session_data)

        # Update last accessed time
        session_info["last_accessed"] = datetime.now().isoformat()
        self.redis_client.setex(
            redis_key,
            self.redis_client.ttl(redis_key),
            json.dumps(session_info)
        )

        return {**token_data, "session_info": session_info}

    def revoke_session(self, token: str):
        redis_key = f"session:{hash(token)}"
        self.redis_client.delete(redis_key)

    def get_user_sessions(self, user_id: str) -> list:
        sessions = []
        for key in self.redis_client.scan_iter(match="session:*"):
            session_data = json.loads(self.redis_client.get(key))
            if session_data.get("user_id") == user_id:
                sessions.append(session_data)
        return sessions

# Usage
session_manager = RedisSessionManager()

# Create session
token = session_manager.create_session("user123", ["read", "write"])

# Validate session
try:
    session_info = session_manager.validate_session(token)
    print(f"Session valid for: {session_info['user_id']}")
except Exception as e:
    print(f"Session invalid: {e}")
```

## Multi-Tenant Applications

```python
from secure_token import SecureTokenManager, Settings
from typing import Dict, Optional

class MultiTenantTokenManager:
    def __init__(self):
        self.tenant_managers: Dict[str, SecureTokenManager] = {}

    def get_tenant_manager(self, tenant_id: str) -> SecureTokenManager:
        if tenant_id not in self.tenant_managers:
            # Each tenant gets its own secret key and settings
            tenant_settings = Settings(
                SECRET_KEY=f"tenant-{tenant_id}-secret-key",
                DEFAULT_EXPIRATION_HOURS=24,
                SALT=f"tenant-{tenant_id}-salt-32-bytes!!".encode()[:32]
            )
            self.tenant_managers[tenant_id] = SecureTokenManager(tenant_settings)

        return self.tenant_managers[tenant_id]

    def generate_tenant_token(self, tenant_id: str, user_id: str,
                            permissions: list = None, **kwargs) -> str:
        manager = self.get_tenant_manager(tenant_id)
        return manager.generate_token(
            user_id=user_id,
            permissions=permissions or [],
            additional_data={
                "tenant_id": tenant_id,
                **kwargs.get("additional_data", {})
            },
            **{k: v for k, v in kwargs.items() if k != "additional_data"}
        )

    def validate_tenant_token(self, tenant_id: str, token: str) -> dict:
        manager = self.get_tenant_manager(tenant_id)
        result = manager.validate_token(token)

        # Verify tenant ID matches
        if result.get("additional_data", {}).get("tenant_id") != tenant_id:
            raise ValueError("Token tenant mismatch")

        return result

# Usage
multi_tenant_manager = MultiTenantTokenManager()

# Generate tokens for different tenants
tenant_a_token = multi_tenant_manager.generate_tenant_token(
    tenant_id="company-a",
    user_id="user123",
    permissions=["read", "write"]
)

tenant_b_token = multi_tenant_manager.generate_tenant_token(
    tenant_id="company-b",
    user_id="user456",
    permissions=["admin"]
)

# Validate tokens
try:
    result_a = multi_tenant_manager.validate_tenant_token("company-a", tenant_a_token)
    print(f"Tenant A user: {result_a['user_id']}")

    # This will fail - wrong tenant
    result_b = multi_tenant_manager.validate_tenant_token("company-a", tenant_b_token)
except ValueError as e:
    print(f"Validation error: {e}")
```

## Performance Optimization

### Token Caching

```python
import time
from functools import lru_cache
from secure_token import SecureTokenManager

class CachedTokenManager:
    def __init__(self, cache_size: int = 1000):
        self.manager = SecureTokenManager()
        self.cache_size = cache_size
        self._validation_cache = {}
        self._cache_timestamps = {}

    @lru_cache(maxsize=1000)
    def _cached_validate(self, token: str, timestamp: int) -> dict:
        """Cache validation results for 5 minutes"""
        return self.manager.validate_token(token)

    def validate_token_cached(self, token: str) -> dict:
        current_time = int(time.time())
        cache_window = current_time // 300  # 5-minute windows

        try:
            return self._cached_validate(token, cache_window)
        except Exception as e:
            # Clear cache entry on error
            self._cached_validate.cache_clear()
            raise e

    def generate_token(self, *args, **kwargs) -> str:
        return self.manager.generate_token(*args, **kwargs)

# Usage
cached_manager = CachedTokenManager()

# Generate token
token = cached_manager.generate_token("user123", ["read", "write"])

# First validation - hits the actual validation
start_time = time.time()
result1 = cached_manager.validate_token_cached(token)
time1 = time.time() - start_time

# Second validation - uses cache
start_time = time.time()
result2 = cached_manager.validate_token_cached(token)
time2 = time.time() - start_time

print(f"First validation: {time1:.4f}s")
print(f"Cached validation: {time2:.4f}s")
print(f"Speedup: {time1/time2:.2f}x")
```

### Batch Operations

```python
from concurrent.futures import ThreadPoolExecutor
from secure_token import SecureTokenManager
import time

class BatchTokenManager:
    def __init__(self, max_workers: int = 10):
        self.manager = SecureTokenManager()
        self.max_workers = max_workers

    def generate_tokens_batch(self, user_requests: list) -> list:
        """Generate multiple tokens in parallel"""
        def generate_single(request):
            return self.manager.generate_token(**request)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            return list(executor.map(generate_single, user_requests))

    def validate_tokens_batch(self, tokens: list) -> list:
        """Validate multiple tokens in parallel"""
        def validate_single(token):
            try:
                return {"success": True, "data": self.manager.validate_token(token)}
            except Exception as e:
                return {"success": False, "error": str(e)}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            return list(executor.map(validate_single, tokens))

# Usage
batch_manager = BatchTokenManager()

# Generate multiple tokens
user_requests = [
    {"user_id": f"user{i}", "permissions": ["read", "write"]}
    for i in range(100)
]

start_time = time.time()
tokens = batch_manager.generate_tokens_batch(user_requests)
generation_time = time.time() - start_time

print(f"Generated {len(tokens)} tokens in {generation_time:.2f}s")
print(f"Rate: {len(tokens)/generation_time:.0f} tokens/second")

# Validate tokens in batch
start_time = time.time()
results = batch_manager.validate_tokens_batch(tokens)
validation_time = time.time() - start_time

successful = sum(1 for r in results if r["success"])
print(f"Validated {successful}/{len(results)} tokens in {validation_time:.2f}s")
print(f"Rate: {len(results)/validation_time:.0f} validations/second")
```

---

**Next:** [Usage Guide](usage-guide.md) | **Back to:** [Tutorial Guide](tutorial-guide.md)
