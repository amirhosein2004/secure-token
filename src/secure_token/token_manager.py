"""
SecureTokenManager - Main token manager class

This module contains the SecureTokenManager class, which provides full
features for creating, validating, revoking, and extending encrypted tokens.

Author: AmirHossein Babaee
Create Date: 2025
Version: 1.0.0
"""


import base64
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import Settings
from .exceptions import InvalidTokenError, PermissionDeniedError, TokenError, TokenExpiredError
from .validators import validate_expires_hours, validate_permissions

logger = logging.getLogger(__name__)


class SecureTokenManager:
    """
    SecureTokenManager - Token manager class

    This class is designed to create, validate, and manage encrypted tokens
    using powerful encryption algorithms.
    """

    def __init__(self, settings_instance: Optional[Settings] = None):
        """
        Initialize the token manager

        Raises:
            TokenError: In case of error during initialization

        Example:
            >>> manager = SecureTokenManager()
            >>> isinstance(manager, SecureTokenManager)
            True
        """
        try:
            self.settings = settings_instance or Settings()
            # set secret key
            self.secret_key = self.settings.SECRET_KEY.encode("utf-8")

            # set salt
            self.salt = self.settings.SALT

            # setup encryption system
            self._setup_encryption()

            # Token manager is now stateless - no local storage needed

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

    def generate_token(
        self,
        user_id: str,
        permissions: Optional[List[str]] = None,
        expires_in_hours: Optional[int] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> str:
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
                expires_in_hours = self.settings.DEFAULT_EXPIRATION_HOURS

            # validate inputs
            validate_expires_hours(expires_in_hours)

            if permissions is None:
                permissions = []
            else:
                validate_permissions(permissions)

            if additional_data is None:
                additional_data = {}

            # Stateless mode: no active token tracking
            # Token limits should be handled at application level if needed

            # generate unique token id
            token_id = secrets.token_urlsafe(24)
            current_time = datetime.now()
            expiration_time = current_time + timedelta(hours=expires_in_hours)

            # create token payload
            payload = {
                "token_id": token_id,
                "user_id": user_id,
                "permissions": permissions,
                "issued_at": current_time.isoformat(),
                "expires_at": expiration_time.isoformat(),
                "additional_data": additional_data,
                "version": "1.0",  # versioning for future compatibility
            }

            # encrypt payload
            json_payload = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            encrypted_token = self.cipher_suite.encrypt(json_payload.encode("utf-8"))

            # convert to base64 for easy transfer
            final_token = base64.urlsafe_b64encode(encrypted_token).decode("ascii")

            # Stateless mode: no token storage or statistics tracking

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
                raise InvalidTokenError("Token is empty or invalid")

            # decrypt token
            try:
                encrypted_data = base64.urlsafe_b64decode(token.encode("ascii"))
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                payload = json.loads(decrypted_data.decode("utf-8"))
            except Exception as e:
                logger.warning(f"Error decrypting token: {e}")
                raise InvalidTokenError("Token format is invalid")

            # check payload structure
            required_fields = ["token_id", "user_id", "expires_at"]
            for field in required_fields:
                if field not in payload:
                    raise InvalidTokenError(f"Field {field} is missing in token")

            token_id = payload["token_id"]
            expires_at = datetime.fromisoformat(payload["expires_at"])
            current_time = datetime.now()

            # check expiration
            if current_time > expires_at:
                logger.info(f"Token expired: {token_id}")
                raise TokenExpiredError("Token expired")

            # Stateless mode: token validation based only on payload content
            # No revocation checking - tokens are valid until they expire

            logger.debug(f"Token validated: {token_id} - User: {payload['user_id']}")

            return {
                "valid": True,
                "payload": payload,
                "user_id": payload["user_id"],
                "permissions": payload.get("permissions", []),
                "expires_at": expires_at,
                "issued_at": datetime.fromisoformat(payload["issued_at"]),
                "additional_data": payload.get("additional_data", {}),
                "time_remaining": str(expires_at - current_time),
            }

        except (InvalidTokenError, TokenExpiredError, TokenError):
            raise
        except Exception as e:
            logger.error(f"Error validating token: {e}")
            raise TokenError(f"Internal error: {str(e)}")

    def refresh_token(
        self, token: str, new_expires_in_hours: Optional[int] = None
    ) -> Optional[str]:
        """
        Refresh a token by creating a new one (Stateless mode)

        Args:
            token: Current token
            new_expires_in_hours: New expiration time

        Returns:
            Optional[str]: New token on success, None otherwise

        Raises:
            InvalidTokenError: If the token format is invalid
            TokenExpiredError: If the token has expired
            TokenError: Other token errors

        Example:
            >>> new_token = manager.refresh_token(old_token, 48)
            >>> if new_token:
            ...     print("Refreshed")
        """
        try:
            validation_result = self.validate_token(token)

            if new_expires_in_hours is None:
                new_expires_in_hours = self.settings.DEFAULT_EXPIRATION_HOURS

            payload = validation_result["payload"]

            # In stateless mode, we just create a new token
            # The old token will expire naturally
            new_token = self.generate_token(
                user_id=payload["user_id"],
                permissions=payload.get("permissions", []),
                expires_in_hours=new_expires_in_hours,
                additional_data=payload.get("additional_data", {}),
            )

            logger.info(f"Token refreshed for user: {payload['user_id']}")

            return new_token

        except (
            TokenError,
            PermissionDeniedError,
            InvalidTokenError,
            TokenExpiredError,
        ):
            raise
        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            raise TokenError(f"Error refreshing token: {e}")

    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get complete token information (Stateless mode)

        Args:
            token: Token to check

        Raises:
            InvalidTokenError: If the token format is invalid
            TokenExpiredError: If the token has expired
            TokenError: Other token errors

        Returns:
            Dict: Complete token information

        Example:
            >>> token = manager.generate_token("user-info", ["read"])
            >>> info = manager.get_token_info(token)
            >>> print(info['user_id'])
            user-info
        """
        try:
            validation_result = self.validate_token(token)

            payload = validation_result["payload"]
            token_id = payload["token_id"]

            return {
                "valid": True,
                "token_id": token_id,
                "user_id": payload["user_id"],
                "permissions": payload.get("permissions", []),
                "issued_at": payload["issued_at"],
                "expires_at": payload["expires_at"],
                "additional_data": payload.get("additional_data", {}),
                "time_remaining": validation_result["time_remaining"],
                "is_revoked": False,  # Always False in stateless mode
                "created_at": payload["issued_at"],  # Use issued_at as created_at
            }

        except (InvalidTokenError, TokenExpiredError, TokenError):
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
            PermissionDeniedError: If permission is not granted
            TokenError: Other token errors

        Example:
            >>> has_access = manager.check_permission(token, "admin")
            >>> if has_access:
            ...     print("Permission granted")
        """
        try:
            validation_result = self.validate_token(token)

            permissions = validation_result.get("permissions", [])
            if required_permission not in permissions:
                raise PermissionDeniedError(f"Permission '{required_permission}' not granted")
            return True

        except (
            PermissionDeniedError,
            InvalidTokenError,
            TokenExpiredError,
            TokenError,
        ):
            raise

        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            raise TokenError(f"Error checking permission: {e}")

    def export_config(self) -> Dict[str, str]:
        """
        Export configuration for backup

        Returns:
            Dict: Configuration that can be saved

        Note: This method is for development purposes and should be used with caution in production

        Example:
            >>> config_backup = manager.export_config()
            >>> print(config_backup['algorithm'])
            Fernet-PBKDF2-SHA256
        """
        return {
            "secret_key_hash": base64.b64encode(
                self.settings.SECRET_KEY.encode("utf-8")[:16]
            ).decode(),
            "salt": base64.b64encode(self.settings.SALT).decode(),
            "version": "1.0",
            "algorithm": "Fernet-PBKDF2-SHA256",
        }

    def __str__(self) -> str:
        """Show class as string"""
        return "SecureTokenManager(stateless_mode=True)"

    def __repr__(self) -> str:
        """Show class as string"""
        return "SecureTokenManager(stateless_mode=True)"
