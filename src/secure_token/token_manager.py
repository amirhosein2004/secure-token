"""
SecureTokenManager - Main token manager class

This module contains the SecureTokenManager class, which provides full
features for creating, validating, revoking, and extending encrypted tokens.

Author: AmirHossein Babaee
Create Date: 2025-08-25
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

from .exceptions import TokenError, PermissionDeniedError
from .validators import validate_user_id, validate_expires_hours, validate_permissions


# logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureTokenManager:
    """
    SecureTokenManager - Token manager class
    
    This class is designed to create, validate, and manage encrypted tokens
    using powerful encryption algorithms.
    """
    
    def __init__(self, secret_key: Optional[str] = None, salt: Optional[bytes] = None):
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
            if secret_key:
                self.secret_key = secret_key.encode('utf-8')
            else:
                self.secret_key = secrets.token_bytes(32)
                logger.info("Random secret key generated")
            
            # set salt
            if salt:
                self.salt = salt
            else:
                self.salt = b'secure_token_salt_2024'  # use random salt in production
            
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
                      expires_in_hours: int = 24,
                      additional_data: Optional[Dict[str, Any]] = None,
                      max_tokens_per_user: int = 10) -> str:
        """
        Generate a new secure token
        
        Args:
            user_id: User ID (required)
            permissions: User permissions list
            expires_in_hours: Token expiration time in hours
            additional_data: Additional data to save in the token
            max_tokens_per_user: Maximum number of active tokens per user
        
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
            
            if len(user_active_tokens) >= max_tokens_per_user:
                raise PermissionDeniedError(f"Maximum {max_tokens_per_user} active tokens allowed")
            
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
        
        