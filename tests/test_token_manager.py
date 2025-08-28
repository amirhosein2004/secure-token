"""
Test suite for SecureTokenManager

This module contains comprehensive tests for the SecureTokenManager class,
including unit tests for all methods and edge cases.

Author: AmirHossein Babaee
Create Date: 2025
Version: 1.0.0
"""

import os
import time
import pytest
from unittest.mock import patch
from datetime import datetime, timedelta
import importlib
from src import config
from src.secure_token import SecureTokenManager
from src.secure_token import (
    TokenError, TokenExpiredError, TokenRevokedError,
    InvalidTokenError, PermissionDeniedError
)


@pytest.fixture
def test_env_vars():
    """Test environment variables fixture"""
    return {
        'SECRET_KEY': 'test_secret_key_for_testing_12345678',
        'SALT': 'test_salt_2024',
        'DEFAULT_EXPIRATION_HOURS': '2',
        'MAX_TOKENS_PER_USER': '3',
        'LOG_LEVEL': 'DEBUG'
    }

@pytest.fixture
def manager(test_env_vars):
    """SecureTokenManager fixture with test environment"""
    with patch.dict(os.environ, test_env_vars):
        # Reload config to pick up test environment variables
        importlib.reload(config)
        
        token_manager = SecureTokenManager()
        yield token_manager
        # Cleanup after test
        token_manager.active_tokens.clear()

class TestSecureTokenManager:
    """Test cases for SecureTokenManager class"""
    
    def test_initialization(self, manager):
        """Test SecureTokenManager initialization"""
        assert manager is not None
        assert manager.secret_key is not None
        assert manager.salt is not None
        assert manager.cipher_suite is not None
        assert len(manager.active_tokens) == 0
        assert 'tokens_generated' in manager.stats
    
    def test_generate_token_basic(self, manager):
        """Test basic token generation"""
        user_id = "test_user_123"
        token = manager.generate_token(user_id)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
        assert manager.stats['tokens_generated'] == 1
    
    def test_generate_token_with_permissions(self, manager):
        """Test token generation with permissions"""
        user_id = "test_user_456"
        permissions = ["read", "write", "admin"]
        
        token = manager.generate_token(
            user_id=user_id,
            permissions=permissions,
            expires_in_hours=1
        )
        
        assert token is not None
        
        # Validate the token and check permissions
        validation_result = manager.validate_token(token)
        assert validation_result['valid'] is True
        assert validation_result['user_id'] == user_id
        assert validation_result['permissions'] == permissions
    
    def test_generate_token_with_additional_data(self, manager):
        """Test token generation with additional data"""
        user_id = "test_user_789"
        additional_data = {
            "department": "IT",
            "role": "developer",
            "employee_id": 12345
        }
        
        token = manager.generate_token(
            user_id=user_id,
            additional_data=additional_data
        )
        
        validation_result = manager.validate_token(token)
        assert validation_result['additional_data'] == additional_data
    
    def test_generate_token_max_limit(self, manager):
        """Test maximum tokens per user limit"""
        user_id = "test_user_limit"
        
        # Generate tokens up to the limit (3 in test config)
        tokens = []
        for i in range(3):
            token = manager.generate_token(user_id)
            tokens.append(token)
        
        # Try to generate one more token - should raise exception
        with pytest.raises(PermissionDeniedError):
            manager.generate_token(user_id)
    
    def test_validate_token_success(self, manager):
        """Test successful token validation"""
        user_id = "test_user_validate"
        token = manager.generate_token(user_id)
        
        result = manager.validate_token(token)
        
        assert result['valid'] is True
        assert result['user_id'] == user_id
        assert isinstance(result['expires_at'], datetime)
        assert isinstance(result['issued_at'], datetime)
    
    def test_validate_token_invalid_format(self, manager):
        """Test validation with invalid token format"""
        invalid_tokens = [
            "invalid_token",
            "12345",
            "short"
        ]
        
        for invalid_token in invalid_tokens:
            with pytest.raises(InvalidTokenError):
                manager.validate_token(invalid_token)
        
        # Test empty string separately
        with pytest.raises(InvalidTokenError):
            manager.validate_token("")
    
    def test_validate_token_expired(self, manager):
        """Test validation of expired token"""
        user_id = "test_user_expired"
        
        # Generate token with very short expiration (1 second)
        token = manager.generate_token(user_id, expires_in_hours=1/3600)  # 1 second
        
        # Wait for token to expire
        time.sleep(2)
        
        with pytest.raises(TokenExpiredError):
            manager.validate_token(token)
    
    def test_revoke_token(self, manager):
        """Test token revocation"""
        user_id = "test_user_revoke"
        token = manager.generate_token(user_id)
        
        # Validate token is initially valid
        result = manager.validate_token(token)
        assert result['valid'] is True
        
        # Revoke the token
        revoke_result = manager.revoke_token(token)
        assert revoke_result is True
        
        # Try to validate revoked token
        with pytest.raises(TokenRevokedError):
            manager.validate_token(token)
    
    def test_refresh_token(self, manager):
        """Test token refresh functionality"""
        user_id = "test_user_refresh"
        permissions = ["read", "write"]
        
        original_token = manager.generate_token(
            user_id=user_id,
            permissions=permissions
        )
        
        # Refresh the token
        new_token = manager.refresh_token(original_token)
        
        assert new_token is not None
        assert original_token != new_token
        
        # Original token should be revoked
        with pytest.raises(TokenRevokedError):
            manager.validate_token(original_token)
        
        # New token should be valid
        result = manager.validate_token(new_token)
        assert result['valid'] is True
        assert result['user_id'] == user_id
        assert result['permissions'] == permissions
    
    def test_refresh_token_with_custom_expiration(self, manager):
        """Test token refresh with custom expiration time"""
        user_id = "test_user_refresh_custom"
        original_token = manager.generate_token(user_id)
        
        # Refresh with custom expiration
        new_token = manager.refresh_token(original_token, new_expires_in_hours=5)
        
        result = manager.validate_token(new_token)
        expires_at = result['expires_at']
        issued_at = result['issued_at']
        
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
            user_id=user_id,
            permissions=permissions,
            additional_data=additional_data
        )
        
        info = manager.get_token_info(token)
        
        assert info['valid'] is True
        assert info['user_id'] == user_id
        assert info['permissions'] == permissions
        assert info['additional_data'] == additional_data
        assert info['is_revoked'] is False
        assert info['token_id'] is not None
    
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
    
    def test_revoke_user_tokens(self, manager):
        """Test revoking all tokens for a user"""
        user_id = "test_user_revoke_all"
        
        # Generate multiple tokens for the user
        tokens = []
        for i in range(3):
            token = manager.generate_token(user_id)
            tokens.append(token)
        
        # Revoke all tokens for the user
        revoked_count = manager.revoke_user_tokens(user_id)
        assert revoked_count == 3
        
        # All tokens should be revoked
        for token in tokens:
            with pytest.raises(TokenRevokedError):
                manager.validate_token(token)
    
    def test_cleanup_expired_tokens(self, manager):
        """Test cleanup of expired tokens"""
        user_id = "test_user_cleanup"
        
        # Generate some tokens with short expiration (1 second each)
        for i in range(2):
            manager.generate_token(user_id, expires_in_hours=1/3600)
        
        # Generate one token with normal expiration
        valid_token = manager.generate_token(user_id, expires_in_hours=1)
        
        # Wait for short tokens to expire
        time.sleep(2)
        
        # Cleanup expired tokens
        cleaned_count = manager.cleanup_expired_tokens()
        assert cleaned_count == 2
        
        # Valid token should still work
        result = manager.validate_token(valid_token)
        assert result['valid'] is True
    
    def test_get_stats(self, manager):
        """Test statistics functionality"""
        user_id = "test_user_stats"
        
        # Generate some tokens
        token1 = manager.generate_token(user_id)
        token2 = manager.generate_token(user_id)
        
        # Validate one token
        manager.validate_token(token1)
        
        # Revoke one token (this also validates it internally)
        manager.revoke_token(token2)
        
        stats = manager.get_stats()
        
        assert stats['total_generated'] == 2
        assert stats['total_validated'] == 2
        assert stats['total_revoked'] == 1
        assert stats['currently_active'] == 1
        assert stats['currently_revoked'] == 1
    
    def test_export_config(self, manager):
        """Test configuration export"""
        config_export = manager.export_config()
        
        assert 'secret_key_hash' in config_export
        assert 'salt' in config_export
        assert 'version' in config_export
        assert 'algorithm' in config_export
        assert config_export['version'] == '1.0'
        assert config_export['algorithm'] == 'Fernet-PBKDF2-SHA256'
    
    def test_string_representations(self, manager):
        """Test __str__ and __repr__ methods"""
        str_repr = str(manager)
        repr_repr = repr(manager)
        
        assert 'SecureTokenManager' in str_repr
        assert 'active=' in str_repr
        assert 'generated=' in str_repr
        
        assert 'SecureTokenManager' in repr_repr
        assert 'tokens_count=' in repr_repr
    
    def test_invalid_user_id(self, manager):
        """Test token generation with invalid user ID"""
        invalid_user_ids = ["", "   ", "a" * 256]  # Empty, whitespace, too long
        
        for invalid_id in invalid_user_ids:
            with pytest.raises(TokenError):
                manager.generate_token(invalid_id)
    
    def test_concurrent_token_operations(self, manager):
        """Test concurrent token operations"""
        import threading
        import queue
        
        results = queue.Queue()
        user_id = "test_user_concurrent"
        
        def generate_tokens():
            try:
                for i in range(2):  # Generate 2 tokens per thread
                    token = manager.generate_token(f"{user_id}_{threading.current_thread().ident}")
                    results.put(('success', token))
            except Exception as e:
                results.put(('error', str(e)))
        
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
            if result_type == 'success':
                success_count += 1
        
        assert success_count == 6  # 3 threads * 2 tokens each


@pytest.fixture
def edge_case_manager():
    """SecureTokenManager fixture for edge case tests"""
    test_env_vars = {
        'SECRET_KEY': 'edge_case_secret_key_12345678',
        'SALT': 'edge_case_salt',
        'DEFAULT_EXPIRATION_HOURS': '1',
        'MAX_TOKENS_PER_USER': '2',
        'LOG_LEVEL': 'WARNING'
    }
    
    with patch.dict(os.environ, test_env_vars):
        importlib.reload(config)
        
        token_manager = SecureTokenManager()
        yield token_manager
        token_manager.active_tokens.clear()

class TestSecureTokenManagerEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_token_with_empty_permissions(self, edge_case_manager):
        """Test token generation with empty permissions list"""
        user_id = "test_user_empty_perms"
        token = edge_case_manager.generate_token(user_id, permissions=[])
        
        result = edge_case_manager.validate_token(token)
        assert result['permissions'] == []
    
    def test_token_with_none_additional_data(self, edge_case_manager):
        """Test token generation with None additional data"""
        user_id = "test_user_none_data"
        token = edge_case_manager.generate_token(user_id, additional_data=None)
        
        result = edge_case_manager.validate_token(token)
        assert result['additional_data'] == {}
    
    def test_refresh_expired_token(self, edge_case_manager):
        """Test refreshing an already expired token"""
        user_id = "test_user_refresh_expired"
        
        # Generate token with very short expiration (1 second)
        token = edge_case_manager.generate_token(user_id, expires_in_hours=1/3600)
        
        # Wait for expiration
        time.sleep(2)
        
        # Try to refresh expired token
        with pytest.raises(TokenExpiredError):
            edge_case_manager.refresh_token(token)
    
    def test_refresh_revoked_token(self, edge_case_manager):
        """Test refreshing a revoked token"""
        user_id = "test_user_refresh_revoked"
        token = edge_case_manager.generate_token(user_id)
        
        # Revoke the token
        edge_case_manager.revoke_token(token)
        
        # Try to refresh revoked token
        with pytest.raises(TokenRevokedError):
            edge_case_manager.refresh_token(token)


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v'])