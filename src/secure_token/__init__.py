"""
SecureToken - Secure token system
Version: 1.0.0
Author: [Amirhossein Babaee]
"""

from .config import Settings, create_settings_instance
from .exceptions import InvalidTokenError, PermissionDeniedError, TokenError, TokenExpiredError
from .token_manager import SecureTokenManager
from .utils import generate_salt, generate_secret_key
from .validators import validate_expires_hours, validate_permissions, validate_user_id

__all__ = [
    "SecureTokenManager",
    "TokenError",
    "TokenExpiredError",
    "InvalidTokenError",
    "PermissionDeniedError",
    "validate_user_id",
    "validate_permissions",
    "validate_expires_hours",
    "create_settings_instance",
    "Settings",
    "generate_secret_key",
    "generate_salt",
]

__version__ = "1.0.0"
__author__ = "Amirhossein Babaee"
__email__ = "amirhoosenbabai82@gmail.com"
__license__ = "MIT"
__copyright__ = "Copyright 2025 Amirhossein Babaee"
__status__ = "Development"
