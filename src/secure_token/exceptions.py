"""Custom exceptions for the token system"""


class TokenError(Exception):
    """General token error"""

    pass


class TokenExpiredError(TokenError):
    """Token expired error"""

    pass


class InvalidTokenError(TokenError):
    """Invalid token error"""

    pass


class PermissionDeniedError(TokenError):
    """Permission denied error"""

    pass
