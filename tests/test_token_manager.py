"""
Test suite for SecureTokenManager

This module contains comprehensive tests for the SecureTokenManager class,
including unit tests for all methods and edge cases.

Author: AmirHossein Babaee
Create Date: 2025
Version: 1.0.0
"""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from src.secure_token import (
    InvalidTokenError,
    PermissionDeniedError,
    SecureTokenManager,
    TokenError,
    TokenExpiredError,
)


class MockSettings:
    """Mock settings for testing"""

    def __init__(self):
        self.SECRET_KEY = "test_secret_key_for_testing_12345678"
        self.SALT = b"test_salt_2024"
        self.DEFAULT_EXPIRATION_HOURS = 2
        self.LOG_LEVEL = "DEBUG"


@pytest.fixture
def manager():
    """SecureTokenManager fixture with test configuration"""
    mock_settings = MockSettings()
    token_manager = SecureTokenManager(settings_instance=mock_settings)
    yield token_manager
    # No cleanup needed in stateless mode


@pytest.fixture
def edge_case_manager():
    """SecureTokenManager fixture for edge case tests"""
    mock_settings = MockSettings()
    mock_settings.DEFAULT_EXPIRATION_HOURS = 1
    mock_settings.LOG_LEVEL = "WARNING"

    token_manager = SecureTokenManager(settings_instance=mock_settings)
    yield token_manager
    # No cleanup needed in stateless mode


class TestSecureTokenManager:
    """Test cases for SecureTokenManager class"""

    def test_initialization(self, manager):
        """Test SecureTokenManager initialization"""
        assert manager is not None
        assert manager.secret_key is not None
        assert manager.salt is not None
        assert manager.cipher_suite is not None

    def test_generate_token_basic(self, manager):
        """Test basic token generation"""
        user_id = "test_user_123"
        token = manager.generate_token(user_id)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_with_permissions(self, manager):
        """Test token generation with permissions"""
        user_id = "test_user_456"
        permissions = ["read", "write", "admin"]

        token = manager.generate_token(user_id=user_id, permissions=permissions, expires_in_hours=1)

        assert token is not None

        # Validate the token and check permissions
        validation_result = manager.validate_token(token)
        assert validation_result["valid"] is True
        assert validation_result["user_id"] == user_id
        assert validation_result["permissions"] == permissions

    def test_generate_token_with_additional_data(self, manager):
        """Test token generation with additional data"""
        user_id = "test_user_789"
        additional_data = {
            "department": "IT",
            "role": "developer",
            "employee_id": 12345,
        }

        token = manager.generate_token(user_id=user_id, additional_data=additional_data)

        validation_result = manager.validate_token(token)
        assert validation_result["additional_data"] == additional_data

    def test_generate_token_multiple_same_user(self, manager):
        """Test generating multiple tokens for same user (stateless mode)"""
        user_id = "test_user_multiple"

        # In stateless mode, we can generate unlimited tokens for same user
        tokens = []
        for i in range(5):  # Generate more than the old limit
            token = manager.generate_token(user_id)
            tokens.append(token)
            # Each token should be valid
            result = manager.validate_token(token)
            assert result["valid"] is True

    def test_validate_token_success(self, manager):
        """Test successful token validation"""
        user_id = "test_user_validate"
        token = manager.generate_token(user_id)

        result = manager.validate_token(token)

        assert result["valid"] is True
        assert result["user_id"] == user_id
        assert isinstance(result["expires_at"], datetime)
        assert isinstance(result["issued_at"], datetime)

    def test_validate_token_invalid_format(self, manager):
        """Test validation with invalid token format"""
        invalid_tokens = ["invalid_token", "12345", "short"]

        for invalid_token in invalid_tokens:
            with pytest.raises(InvalidTokenError):
                manager.validate_token(invalid_token)

        # Test empty string separately
        with pytest.raises(InvalidTokenError):
            manager.validate_token("")

    def test_validate_token_expired(self, manager):
        """Test validation of expired token"""
        user_id = "test_user_expired"

        # Create a token with very short expiration
        token = manager.generate_token(user_id, expires_in_hours=1)

        # Mock datetime to simulate time passing
        with patch("src.secure_token.token_manager.datetime") as mock_datetime:
            # Mock current time to be 2 hours in the future
            future_time = datetime.now() + timedelta(hours=2)
            mock_datetime.now.return_value = future_time
            mock_datetime.fromisoformat = datetime.fromisoformat

            # Now validate with future time (token should be expired)
            with pytest.raises(TokenExpiredError):
                manager.validate_token(token)

    def test_refresh_token(self, manager):
        """Test token refresh functionality in stateless mode"""
        user_id = "test_user_refresh"
        permissions = ["read", "write"]

        original_token = manager.generate_token(user_id=user_id, permissions=permissions)

        # Refresh the token
        new_token = manager.refresh_token(original_token)

        assert new_token is not None
        assert original_token != new_token

        # In stateless mode, original token remains valid until it expires
        result = manager.validate_token(original_token)
        assert result["valid"] is True

        # New token should also be valid
        result = manager.validate_token(new_token)
        assert result["valid"] is True
        assert result["user_id"] == user_id
        assert result["permissions"] == permissions

    def test_refresh_token_with_custom_expiration(self, manager):
        """Test token refresh with custom expiration time"""
        user_id = "test_user_refresh_custom"
        original_token = manager.generate_token(user_id)

        # Refresh with custom expiration
        new_token = manager.refresh_token(original_token, new_expires_in_hours=5)

        result = manager.validate_token(new_token)
        expires_at = result["expires_at"]
        issued_at = result["issued_at"]

        # Check that expiration is approximately 5 hours from issue time
        expected_expiration = issued_at + timedelta(hours=5)
        time_diff = abs((expires_at - expected_expiration).total_seconds())
        assert time_diff < 60  # Allow 1 minute tolerance

    def test_get_token_info(self, manager):
        """Test getting complete token information"""
        user_id = "test_user_info"
        permissions = ["admin"]
        additional_data = {"role": "manager"}

        token = manager.generate_token(
            user_id=user_id, permissions=permissions, additional_data=additional_data
        )

        info = manager.get_token_info(token)

        assert info["valid"] is True
        assert info["user_id"] == user_id
        assert info["permissions"] == permissions
        assert info["additional_data"] == additional_data
        assert info["is_revoked"] is False  # Always False in stateless mode
        assert info["token_id"] is not None

    def test_check_permission_success(self, manager):
        """Test successful permission check"""
        user_id = "test_user_perm"
        permissions = ["read", "write", "admin"]

        token = manager.generate_token(user_id, permissions=permissions)

        # Check existing permissions
        assert manager.check_permission(token, "read") is True
        assert manager.check_permission(token, "write") is True
        assert manager.check_permission(token, "admin") is True

    def test_check_permission_denied(self, manager):
        """Test permission check denial"""
        user_id = "test_user_no_perm"
        permissions = ["read"]

        token = manager.generate_token(user_id, permissions=permissions)

        # Check non-existing permission
        with pytest.raises(PermissionDeniedError):
            manager.check_permission(token, "admin")

    def test_export_config(self, manager):
        """Test configuration export"""
        config_export = manager.export_config()

        assert "secret_key_hash" in config_export
        assert "salt" in config_export
        assert "version" in config_export
        assert "algorithm" in config_export
        assert config_export["version"] == "1.0"
        assert config_export["algorithm"] == "Fernet-PBKDF2-SHA256"

    def test_string_representations(self, manager):
        """Test __str__ and __repr__ methods"""
        str_repr = str(manager)
        repr_repr = repr(manager)

        assert "SecureTokenManager" in str_repr
        assert "stateless_mode=True" in str_repr

        assert "SecureTokenManager" in repr_repr
        assert "stateless_mode=True" in repr_repr

    def test_concurrent_token_operations(self, manager):
        """Test concurrent token operations"""
        import queue
        import threading

        results = queue.Queue()
        user_base_id = "test_user_concurrent"

        def generate_tokens():
            try:
                for i in range(2):  # Generate 2 tokens per thread
                    user_id = f"{user_base_id}_{threading.current_thread().ident}_{i}"
                    token = manager.generate_token(user_id)
                    results.put(("success", token))
            except Exception as e:
                results.put(("error", str(e)))

        # Create and start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=generate_tokens)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results
        success_count = 0
        while not results.empty():
            result_type, result_value = results.get()
            if result_type == "success":
                success_count += 1

        assert success_count == 6  # 3 threads * 2 tokens each


class TestSecureTokenManagerEdgeCases:
    """Test edge cases and error conditions"""

    def test_token_with_empty_permissions(self, edge_case_manager):
        """Test token generation with empty permissions list"""
        user_id = "test_user_empty_perms"
        token = edge_case_manager.generate_token(user_id, permissions=[])

        result = edge_case_manager.validate_token(token)
        assert result["permissions"] == []

    def test_token_with_none_additional_data(self, edge_case_manager):
        """Test token generation with None additional data"""
        user_id = "test_user_none_data"
        token = edge_case_manager.generate_token(user_id, additional_data=None)

        result = edge_case_manager.validate_token(token)
        assert result["additional_data"] == {}

    def test_refresh_expired_token(self, edge_case_manager):
        """Test refreshing an already expired token"""
        user_id = "test_user_refresh_expired"

        # Create a token with short expiration
        token = edge_case_manager.generate_token(user_id, expires_in_hours=1)

        # Mock datetime to simulate time passing
        with patch("src.secure_token.token_manager.datetime") as mock_datetime:
            # Mock current time to be 2 hours in the future
            future_time = datetime.now() + timedelta(hours=2)
            mock_datetime.now.return_value = future_time
            mock_datetime.fromisoformat = datetime.fromisoformat

            # Try to refresh expired token
            with pytest.raises(TokenExpiredError):
                edge_case_manager.refresh_token(token)

    def test_token_with_special_characters_in_data(self, edge_case_manager):
        """Test token with special characters in additional data"""
        user_id = "test_user_special_chars"
        additional_data = {
            "name": "احمد حسین بابایی",  # Persian text
            "description": "Special chars: @#$%^&*()",
            "unicode": "🔐🎯✅",  # Emojis
        }

        token = edge_case_manager.generate_token(user_id=user_id, additional_data=additional_data)

        result = edge_case_manager.validate_token(token)
        assert result["additional_data"] == additional_data

    def test_token_with_large_additional_data(self, edge_case_manager):
        """Test token with large additional data"""
        user_id = "test_user_large_data"
        additional_data = {
            "large_text": "x" * 1000,  # Large string
            "numbers": list(range(100)),  # Large list
            "nested": {"level1": {"level2": {"level3": "deep_value"}}},
        }

        token = edge_case_manager.generate_token(user_id=user_id, additional_data=additional_data)

        result = edge_case_manager.validate_token(token)
        assert result["additional_data"] == additional_data

    def test_multiple_permission_checks(self, edge_case_manager):
        """Test multiple permission checks on same token"""
        user_id = "test_user_multi_perm"
        permissions = ["read", "write", "delete", "admin"]

        token = edge_case_manager.generate_token(user_id, permissions=permissions)

        # Check all permissions
        for permission in permissions:
            assert edge_case_manager.check_permission(token, permission) is True

        # Check invalid permission
        with pytest.raises(PermissionDeniedError):
            edge_case_manager.check_permission(token, "super_admin")

    def test_token_with_zero_expiration(self, edge_case_manager):
        """Test token generation with zero expiration time"""
        user_id = "test_user_zero_exp"

        with pytest.raises(TokenError):
            edge_case_manager.generate_token(user_id, expires_in_hours=0)

    def test_token_with_negative_expiration(self, edge_case_manager):
        """Test token generation with negative expiration time"""
        user_id = "test_user_neg_exp"

        with pytest.raises(TokenError):
            edge_case_manager.generate_token(user_id, expires_in_hours=-1)


class TestTokenIntegration:
    """Integration tests for complete token workflow"""

    def test_complete_token_lifecycle(self, manager):
        """Test complete token lifecycle: generate -> validate -> use -> refresh -> revoke"""
        user_id = "integration_user"
        permissions = ["read", "write"]
        additional_data = {"department": "Engineering"}

        # 1. Generate token
        token = manager.generate_token(
            user_id=user_id,
            permissions=permissions,
            additional_data=additional_data,
            expires_in_hours=24,
        )
        assert token is not None

        # 2. Validate token
        validation = manager.validate_token(token)
        assert validation["valid"] is True
        assert validation["user_id"] == user_id

        # 3. Check permissions
        assert manager.check_permission(token, "read") is True
        assert manager.check_permission(token, "write") is True

        # 4. Get token info
        info = manager.get_token_info(token)
        assert info["additional_data"] == additional_data

        # 5. Refresh token
        new_token = manager.refresh_token(token)
        assert new_token != token

        # 6. In stateless mode, old token remains valid
        old_validation = manager.validate_token(token)
        assert old_validation["valid"] is True

        # 7. Verify new token works
        new_validation = manager.validate_token(new_token)
        assert new_validation["valid"] is True

        # 8. Verify both tokens remain valid in stateless mode
        final_validation = manager.validate_token(new_token)
        assert final_validation["valid"] is True

    def test_bulk_operations(self, manager):
        """Test bulk token operations"""
        base_user = "bulk_user"
        tokens = []

        # Generate multiple tokens for different users
        for i in range(5):
            user_id = f"{base_user}_{i}"
            token = manager.generate_token(user_id, permissions=["read"])
            tokens.append((user_id, token))

        # Validate all tokens
        for user_id, token in tokens:
            result = manager.validate_token(token)
            assert result["user_id"] == user_id

        # Verify all tokens remain valid in stateless mode
        for user_id, token in tokens:
            result = manager.validate_token(token)
            assert result["valid"] is True


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
