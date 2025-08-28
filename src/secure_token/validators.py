"""Input validators"""

import re
from typing import List
from .exceptions import TokenError

def validate_user_id(user_id: str) -> bool:
    """Validate user id"""
    if not isinstance(user_id, str):
        raise TokenError("User id must be a string")
    
    if len(user_id) < 3 or len(user_id) > 50:
        raise TokenError("User id must be between 3 and 50 characters")
    
    if not re.match(r'^[a-zA-Z0-9_\u0600-\u06FF]+$', user_id):
        raise TokenError("User id can only contain letters, numbers and underscores")
    
    return True

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

def validate_expires_hours(hours: int) -> bool:
    """Validate expires hours"""
    if not isinstance(hours, int):
        raise TokenError("Expires hours must be an integer")
    
    if hours < 1 or hours > 8760:  # maximum one year
        raise TokenError("Expires hours must be between 1 and 8760 hours")
    
    return True