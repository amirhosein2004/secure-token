import os
import secrets


def generate_secret_key(length: int = 32) -> str:
    """Generate a strong random secret key"""
    return secrets.token_urlsafe(length)


def generate_salt(length: int = 16) -> bytes:
    """Generate a secure random salt"""
    return os.urandom(length)
