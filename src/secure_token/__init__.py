"""
SecureToken - Secure token system
Version: 1.0.0
Author: [Amirhossein Babaee]
"""

from .token_manager import SecureTokenManager
from .exceptions import TokenError, TokenExpiredError, TokenRevokedError, InvalidTokenError, PermissionDeniedError
from .validators import validate_user_id, validate_permissions, validate_expires_hours

__all__ = [
    'SecureTokenManager',
    'TokenError',
    'TokenExpiredError',
    'TokenRevokedError',
    'InvalidTokenError',
    'PermissionDeniedError',
    'validate_user_id',
    'validate_permissions',
    'validate_expires_hours'
]

__version__ = '1.0.0'
__author__ = 'Amirhossein Babaee'
__email__ = 'amirhoosenbabai82@gmail.com'
__license__ = 'MIT'
__copyright__ = 'Copyright 2025 Amirhossein Babaee'
__status__ = 'Development'