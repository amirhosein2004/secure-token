"""
Simple Basic Example - SecureTokenManager

This example shows simple usage of SecureTokenManager (Stateless Mode):
- Create token
- Validate token
- Check permissions
- Refresh token
- Get token information

Author: AmirHossein Babaee
Date: 2025
"""

from src.secure_token import (
    InvalidTokenError,
    PermissionDeniedError,
    SecureTokenManager,
    TokenExpiredError,
)


def main():
    print("=== SecureTokenManager - Simple Example ===\n")

    # 1. Initialize token manager
    print("1. Initialize token manager...")
    manager = SecureTokenManager()
    print("✅ Initialized successfully\n")

    # 2. Create a simple token
    print("2. Create token for user...")
    token = manager.generate_token(user_id="john_doe", expires_in_hours=2)
    print(f"✅ Token created: {len(token)} characters\n")

    # 3. Validate the token
    print("3. Validate token...")
    result = manager.validate_token(token)
    print(f"✅ Token valid for user: {result['user_id']}")
    print(f"   Expires: {result['expires_at'].strftime('%H:%M:%S')}\n")

    # 4. Create token with permissions
    print("4. Create token with permissions...")
    admin_token = manager.generate_token(
        user_id="admin_user", permissions=["read", "write", "admin"], expires_in_hours=1
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

    # 6. Get token information
    print("6. Get token information...")
    token_info = manager.get_token_info(admin_token)
    print(f"✅ Token ID: {token_info['token_id'][:8]}...")
    print(f"✅ User: {token_info['user_id']}")
    print(f"✅ Permissions: {token_info['permissions']}")
    print(f"✅ Time remaining: {token_info['time_remaining']}")
    print()

    # 7. Refresh token
    print("7. Refresh token...")
    try:
        new_token = manager.refresh_token(token, new_expires_in_hours=4)
        if new_token:
            print("✅ Token refreshed successfully")
            print(f"   New token length: {len(new_token)} characters")
        else:
            print("❌ Token refresh failed")
    except (InvalidTokenError, TokenExpiredError) as e:
        print(f"❌ Token refresh failed: {e}")
    print()

    # 8. Export configuration
    print("8. Export configuration...")
    config = manager.export_config()
    print(f"✅ Algorithm: {config['algorithm']}")
    print(f"✅ Version: {config['version']}")
    print(f"✅ Salt (first 16 chars): {config['salt'][:16]}...")

    print("\n=== Example Complete ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}")
