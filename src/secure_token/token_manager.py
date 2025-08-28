"""
SecureTokenManager - Main token manager class

This module contains the SecureTokenManager class, which provides full
features for creating, validating, revoking, and extending encrypted tokens.

Author: AmirHossein Babaee
Create Date: 2025
Version: 1.0.0
"""


import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import (
    TokenError, TokenExpiredError, TokenRevokedError, 
    InvalidTokenError, PermissionDeniedError
)
from .validators import validate_user_id, validate_expires_hours, validate_permissions
from src import config

# logging configuration
logging.basicConfig(level=config.LOG_LEVEL)
logger = logging.getLogger(__name__)


class SecureTokenManager:
    """
    SecureTokenManager - Token manager class
    
    This class is designed to create, validate, and manage encrypted tokens
    using powerful encryption algorithms.
    """
    
    def __init__(self):
        """
        Initialize the token manager
        
        Args:
            secret_key: Secret key for encryption (optional)
            salt: Salt for key strengthening (optional)
        
        Raises:
            TokenError: In case of error during initialization
        """
        try:
            # set secret key
            if config.SECRET_KEY:
                self.secret_key = config.SECRET_KEY.encode('utf-8')
            else:
                self.secret_key = secrets.token_bytes(32)
                logger.warning("SECRET_KEY not found in environment variables. Using a random key.")
            
            # set salt
            self.salt = config.SALT  
            
            # setup encryption system
            self._setup_encryption()
            
            # save temporary active tokens (use database in production)
            self.active_tokens = {}
            
            # usage statistics
            self.stats = {
                'tokens_generated': 0,
                'tokens_validated': 0,
                'tokens_revoked': 0,
                'tokens_expired': 0
            }
            
            logger.info("SecureTokenManager initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing SecureTokenManager: {e}")
            raise TokenError(f"Error initializing: {e}")
    
    def _setup_encryption(self):
        """
        Setup encryption system with Fernet and PBKDF2
        
        Uses PBKDF2 to strengthen the key, which increases security against brute force attacks.
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,  # higher number for better security
            )
            
            # generate final key
            key = base64.urlsafe_b64encode(kdf.derive(self.secret_key))
            self.cipher_suite = Fernet(key)
            
            logger.debug("Encryption system setup successfully")
            
        except Exception as e:
            logger.error(f"Error setting up encryption: {e}")
            raise TokenError(f"Error setting up encryption: {e}")
        
    def generate_token(self, 
                      user_id: str, 
                      permissions: Optional[List[str]] = None,
                      expires_in_hours: int = None,
                      additional_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a new secure token
        
        Args:
            user_id: User ID (required)
            permissions: User permissions list
            expires_in_hours: Token expiration time in hours
            additional_data: Additional data to save in the token
        
        Returns:
            str: Encrypted token
        
        Raises:
            TokenError: In case of error during token generation
            PermissionDeniedError: In case of exceeding the maximum number of active tokens
        
        Example:
            >>> token = manager.generate_token("user123", ["read", "write"], 12)
            >>> print(len(token) > 0)  # True
        """
        try:
            # set default expiration if not provided
            if expires_in_hours is None:
                expires_in_hours = config.DEFAULT_EXPIRATION_HOURS
                
            # validate inputs
            validate_user_id(user_id)
            validate_expires_hours(expires_in_hours)
            
            if permissions is None:
                permissions = []
            else:
                validate_permissions(permissions)
            
            if additional_data is None:
                additional_data = {}
            
            # check user active tokens
            user_active_tokens = [
                token_info for token_info in self.active_tokens.values()
                if (token_info['user_id'] == user_id and 
                    not token_info['is_revoked'] and
                    token_info['expires_at'] > datetime.now())
            ]
            
            if len(user_active_tokens) >= config.MAX_TOKENS_PER_USER:
                raise PermissionDeniedError(f"Maximum {config.MAX_TOKENS_PER_USER} active tokens allowed")
            
            # generate unique token id
            token_id = secrets.token_urlsafe(24)
            current_time = datetime.now()
            expiration_time = current_time + timedelta(hours=expires_in_hours)
            
            # create token payload
            payload = {
                'token_id': token_id,
                'user_id': user_id,
                'permissions': permissions,
                'issued_at': current_time.isoformat(),
                'expires_at': expiration_time.isoformat(),
                'additional_data': additional_data,
                'version': '1.0'  # versioning for future compatibility
            }
            
            # encrypt payload
            json_payload = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
            encrypted_token = self.cipher_suite.encrypt(json_payload.encode('utf-8'))
            
            # convert to base64 for easy transfer
            final_token = base64.urlsafe_b64encode(encrypted_token).decode('ascii')
            
            # save token information
            self.active_tokens[token_id] = {
                'user_id': user_id,
                'permissions': permissions,
                'expires_at': expiration_time,
                'created_at': current_time,
                'is_revoked': False,
                'additional_data': additional_data
            }
            
            # update statistics
            self.stats['tokens_generated'] += 1
            
            logger.info(f"New token generated for user {user_id} - ID: {token_id}")
            
            return final_token
            
        except (TokenError, PermissionDeniedError):
            raise
        except Exception as e:
            logger.error(f"Error generating token: {e}")
            raise TokenError(f"Error generating token: {e}")

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a token
        
        Args:
            token: Token to validate
        
        Returns:
            Dict: Result of validation including status and token information

        Raises:
            InvalidTokenError: If the token format is invalid
            TokenExpiredError: If the token has expired
            TokenRevokedError: If the token has been revoked
            TokenError: Other token errors
        
        Example:
            >>> result = manager.validate_token(token)
            >>> if result['valid']:
            ...     print(f"user: {result['user_id']}")
        """
        try:
            if not isinstance(token, str) or not token.strip():
                raise InvalidTokenError('Token is empty or invalid')
            
            # decrypt token
            try:
                encrypted_data = base64.urlsafe_b64decode(token.encode('ascii'))
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                payload = json.loads(decrypted_data.decode('utf-8'))
            except Exception as e:
                logger.warning(f"Error decrypting token: {e}")
                raise InvalidTokenError('Token format is invalid')
            
            # check payload structure
            required_fields = ['token_id', 'user_id', 'expires_at']
            for field in required_fields:
                if field not in payload:
                    raise InvalidTokenError(f'Field {field} is missing in token')
            
            token_id = payload['token_id']
            expires_at = datetime.fromisoformat(payload['expires_at'])
            current_time = datetime.now()
            
            # check expiration
            if current_time > expires_at:
                self.stats['tokens_expired'] += 1
                logger.info(f"Token expired: {token_id}")
                raise TokenExpiredError('Token expired')
            
            # check if token exists in active tokens
            if token_id not in self.active_tokens:
                raise InvalidTokenError('Token not found in active tokens')
            
            token_info = self.active_tokens[token_id]
            
            # check if token is revoked
            if token_info['is_revoked']:
                raise TokenRevokedError('Token revoked')
            
            # update statistics
            self.stats['tokens_validated'] += 1
            
            logger.debug(f"Token validated: {token_id} - User: {payload['user_id']}")
            
            return {
                'valid': True,
                'payload': payload,
                'user_id': payload['user_id'],
                'permissions': payload.get('permissions', []),
                'expires_at': expires_at,
                'issued_at': datetime.fromisoformat(payload['issued_at']),
                'additional_data': payload.get('additional_data', {}),
                'time_remaining': str(expires_at - current_time)
            }
            
        except (InvalidTokenError, TokenExpiredError, TokenRevokedError, TokenError):
            raise
        except Exception as e:
            logger.error(f"Error validating token: {e}")
            raise TokenError(f'Internal error: {str(e)}')
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token
        
        Args:
            token: Token to revoke
        
        Returns:
            bool: True on success

        Raises:
            InvalidTokenError: If the token format is invalid
            TokenExpiredError: If the token has expired
            TokenRevokedError: If the token has been revoked
            TokenError: Other token errors
        
        Example:
            >>> success = manager.revoke_token(token)
            >>> print(f"Revoked: {success}")
        """
        try:
            validation_result = self.validate_token(token)
            
            token_id = validation_result['payload']['token_id']
            user_id = validation_result['user_id']
            
            # mark as revoked
            self.active_tokens[token_id]['is_revoked'] = True
            self.active_tokens[token_id]['revoked_at'] = datetime.now()
            
            # update statistics
            self.stats['tokens_revoked'] += 1
            
            logger.info(f"Token revoked: {token_id} - User: {user_id}")
            
            return True
            
        except (InvalidTokenError, TokenExpiredError, TokenRevokedError, TokenError):
            raise
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            raise TokenError(f"Error revoking token: {e}")
    
    def refresh_token(self, token: str, new_expires_in_hours: int = None) -> Optional[str]:
        """
        Refresh a token by creating a new one
        
        Args:
            token: Current token
            new_expires_in_hours: New expiration time
        
        Returns:
            Optional[str]: New token on success, None otherwise
        
        Raises:
            InvalidTokenError: If the token format is invalid
            TokenExpiredError: If the token has expired
            TokenRevokedError: If the token has been revoked
            PermissionDeniedError: If the token does not have the required permission
            TokenError: Other token errors

        Example:
            >>> new_token = manager.refresh_token(old_token, 48)
            >>> if new_token:
            ...     print("Refreshed")
        """
        try:
            validation_result = self.validate_token(token)
            
            if new_expires_in_hours is None:
                new_expires_in_hours = config.DEFAULT_EXPIRATION_HOURS
            
            payload = validation_result['payload']
            
            # Revoke the old token
            self.revoke_token(token)
            
            # Create a new token with similar information
            new_token = self.generate_token(
                user_id=payload['user_id'],
                permissions=payload.get('permissions', []),
                expires_in_hours=new_expires_in_hours,
                additional_data=payload.get('additional_data', {})
            )
            
            logger.info(f"Token refreshed for user: {payload['user_id']}")
            
            return new_token
            
        except (TokenError, PermissionDeniedError, InvalidTokenError, TokenExpiredError, TokenRevokedError):
            raise
        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            raise TokenError(f"Error refreshing token: {e}")
    
    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get complete token information
        
        Args:
            token: Token to check
        
        Raises:
            InvalidTokenError: If the token format is invalid
            TokenExpiredError: If the token has expired
            TokenRevokedError: If the token has been revoked
            TokenError: Other token errors

        Returns:
            Dict: Complete token information
        """
        try:
            validation_result = self.validate_token(token)
            
            payload = validation_result['payload']
            token_id = payload['token_id']
            
            # Get additional info from memory
            stored_info = self.active_tokens.get(token_id, {})
            
            return {
                'valid': True,
                'token_id': token_id,
                'user_id': payload['user_id'],
                'permissions': payload.get('permissions', []),
                'issued_at': payload['issued_at'],
                'expires_at': payload['expires_at'],
                'additional_data': payload.get('additional_data', {}),
                'time_remaining': validation_result['time_remaining'],
                'is_revoked': stored_info.get('is_revoked', False),
                'created_at': stored_info.get('created_at', '').isoformat() if stored_info.get('created_at') else None
            }

        except (InvalidTokenError, TokenExpiredError, TokenRevokedError, TokenError):
            raise
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            raise TokenError(f"Error getting token info: {e}")
    
    def check_permission(self, token: str, required_permission: str) -> bool:
        """
        Check for a specific permission in the token
        
        Args:
            token: Token to check
            required_permission: Permission to check
        
        Returns:
            bool: True if permission exists

        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token is expired
            TokenRevokedError: If token is revoked
            PermissionDeniedError: If permission is not granted
            TokenError: Other token errors
        
        Example:
            >>> has_access = manager.check_permission(token, "admin")
            >>> if has_access:
            ...     print("Permission granted")
        """
        try:
            validation_result = self.validate_token(token)
            
            permissions = validation_result.get('permissions', [])
            if required_permission not in permissions:
                raise PermissionDeniedError(f"Permission '{required_permission}' not granted")
            return True

        except (PermissionDeniedError, InvalidTokenError, TokenExpiredError, TokenRevokedError, TokenError):
            raise

        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            raise TokenError(f"Error checking permission: {e}")
    
    def revoke_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user
        
        Args:
            user_id: User ID
        
        Raises:
            TokenError: Other errors

        Returns:
            int: Number of revoked tokens
        """
        try:
            validate_user_id(user_id)

            revoked_count = 0
            current_time = datetime.now()
            
            for token_id, token_info in self.active_tokens.items():
                if (token_info['user_id'] == user_id and 
                    not token_info['is_revoked'] and
                    token_info['expires_at'] > current_time):
                    
                    token_info['is_revoked'] = True
                    token_info['revoked_at'] = current_time
                    revoked_count += 1
            
            self.stats['tokens_revoked'] += revoked_count
            logger.info(f"{revoked_count} tokens revoked for user {user_id}")
            
            return revoked_count

        except (TokenError):
            raise
        except Exception as e:
            logger.error(f"Error revoking user tokens: {e}")
            raise TokenError(f"Error revoking user tokens: {e}")
    
    def cleanup_expired_tokens(self) -> int:
        """
        Remove expired and revoked tokens
        
        Returns:
            int: Number of tokens cleaned up

        Raises:
            TokenError: Other errors
        """
        try:
            current_time = datetime.now()
            expired_tokens = []
            
            for token_id, token_info in self.active_tokens.items():
                if (current_time > token_info['expires_at'] or 
                    token_info['is_revoked']):
                    expired_tokens.append(token_id)
            
            # حذف توکن‌های منقضی
            for token_id in expired_tokens:
                del self.active_tokens[token_id]
            
            logger.info(f"{len(expired_tokens)} expired tokens cleaned up")
            
            return len(expired_tokens)
            
        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {e}")
            raise TokenError(f"Error cleaning up expired tokens: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about token usage
        
        Returns:
            Dict: Complete statistics including token counts and operations
        """
        current_time = datetime.now()
        
        active_count = len([
            t for t in self.active_tokens.values()
            if not t['is_revoked'] and t['expires_at'] > current_time
        ])
        
        expired_count = len([
            t for t in self.active_tokens.values()
            if t['expires_at'] <= current_time
        ])
        
        revoked_count = len([
            t for t in self.active_tokens.values()
            if t['is_revoked']
        ])
        
        return {
            'total_generated': self.stats['tokens_generated'],
            'total_validated': self.stats['tokens_validated'],
            'total_revoked': self.stats['tokens_revoked'],
            'total_expired': self.stats['tokens_expired'],
            'currently_active': active_count,
            'currently_expired': expired_count,
            'currently_revoked': revoked_count,
            'cleanup_needed': expired_count + revoked_count
        }
    
    def export_config(self) -> Dict[str, str]:
        """
        Export configuration for backup
        
        Returns:
            Dict: Configuration that can be saved
        
        Note: This method is for development purposes and should be used with caution in production
        """
        return {
            'secret_key_hash': base64.b64encode(
                config.SECRET_KEY.encode('utf-8')[:16]
            ).decode(),
            'salt': base64.b64encode(config.SALT).decode(),
            'version': '1.0',
            'algorithm': 'Fernet-PBKDF2-SHA256'
        }
    
    def __str__(self) -> str:
        """Show class as string"""
        stats = self.get_stats()
        return (f"SecureTokenManager("
                f"active={stats['currently_active']}, "
                f"generated={stats['total_generated']}"
                f")")
    
    def __repr__(self) -> str:
        """Show class as string"""
        return f"SecureTokenManager(tokens_count={len(self.active_tokens)})"