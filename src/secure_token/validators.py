"""Input validators"""

import re
from typing import List

from .exceptions import TokenError


def validate_permissions(permissions: List[str]) -> bool:
    """Validate permissions"""
    if not isinstance(permissions, list):
        raise TokenError("Permissions must be a list")

    for perm in permissions:
        if not isinstance(perm, str):
            raise TokenError("Each permission must be a string")

        if len(perm) < 2 or len(perm) > 30:
            raise TokenError("Permission length must be between 2 and 30 characters")

    return True


def validate_expires_hours(hours) -> bool:
    """Validate expires hours"""
    if not isinstance(hours, (int, float)):
        raise TokenError("Expires hours must be a number")

    if hours <= 0 or hours > 8760:  # maximum one year
        raise TokenError("Expires hours must be between 0 and 8760 hours")

    return True


def validate_secret_key(secret_key: str) -> bool:
    """Validate secret key strength"""
    if not isinstance(secret_key, str):
        raise TokenError("SECRET_KEY must be a string")

    if len(secret_key) < 16:
        raise TokenError("SECRET_KEY must be at least 16 characters long")

    # Optional: enforce complexity (letters + numbers + special chars)
    if not re.search(r"[A-Z]", secret_key) or not re.search(r"[a-z]", secret_key):
        raise TokenError("SECRET_KEY must contain both uppercase and lowercase letters")

    if not re.search(r"\d", secret_key):
        raise TokenError("SECRET_KEY must contain at least one number")

    if not re.search(r"[@$!%*?&#]", secret_key):
        raise TokenError("SECRET_KEY must contain at least one special character")

    return True


def validate_salt(salt: bytes) -> bool:
    """Validate salt"""
    if not isinstance(salt, (bytes, bytearray)):
        raise TokenError("SALT must be bytes")

    if len(salt) < 16:
        raise TokenError("SALT must be at least 16 bytes long")

    return True
