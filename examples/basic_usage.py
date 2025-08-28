"""
Simple Basic Example - SecureTokenManager

This example shows simple usage of SecureTokenManager:
- Create token
- Validate token
- Check permissions
- Revoke token

Author: AmirHossein Babaee  
Date: 2025
"""

from src.secure_token import SecureTokenManager
from src.secure_token import (
    TokenRevokedError,
    PermissionDeniedError
)


def main():
    print("=== SecureTokenManager - Simple Example ===\n")
    
    # 1. Initialize token manager
    print("1. Initialize token manager...")
    manager = SecureTokenManager()
    print("✅ Initialized successfully\n")
    
    # 2. Create a simple token
    print("2. Create token for user...")
    token = manager.generate_token(
        user_id="john_doe",
        expires_in_hours=2
    )
    print(f"✅ Token created: {len(token)} characters\n")
    
    # 3. Validate the token
    print("3. Validate token...")
    result = manager.validate_token(token)
    print(f"✅ Token valid for user: {result['user_id']}")
    print(f"   Expires: {result['expires_at'].strftime('%H:%M:%S')}\n")
    
    # 4. Create token with permissions
    print("4. Create token with permissions...")
    admin_token = manager.generate_token(
        user_id="admin_user",
        permissions=["read", "write", "admin"],
        expires_in_hours=1
    )
    print("✅ Admin token created\n")
    
    # 5. Check permissions
    print("5. Check permissions...")
    
    # Check valid permission
    try:
        manager.check_permission(admin_token, "write")
        print("✅ Write permission: OK")
    except PermissionDeniedError:
        print("❌ Write permission: DENIED")
    
    # Check invalid permission  
    try:
        manager.check_permission(admin_token, "delete")
        print("✅ Delete permission: OK")
    except PermissionDeniedError:
        print("❌ Delete permission: DENIED")
    
    print()
    
    # 6. Revoke token
    print("6. Revoke token...")
    manager.revoke_token(token)
    print("✅ Token revoked")
    
    # Try to use revoked token
    try:
        manager.validate_token(token)
        print("❌ Revoked token still works!")
    except TokenRevokedError:
        print("✅ Revoked token correctly blocked\n")
    
    # 7. Show statistics
    print("7. Show statistics...")
    stats = manager.get_stats()
    print(f"✅ Generated: {stats['total_generated']}")
    print(f"✅ Active: {stats['currently_active']}")
    print(f"✅ Revoked: {stats['currently_revoked']}")
    
    print("\n=== Example Complete ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}")

