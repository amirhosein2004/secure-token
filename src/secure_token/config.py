from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings

from .utils import generate_salt, generate_secret_key
from .validators import validate_expires_hours, validate_salt, validate_secret_key


class Settings(BaseSettings):
    """
    Manages application settings using Pydantic, loading from .env files.
    """

    # --- Security ---
    SECRET_KEY: str = Field(
        default_factory=lambda: generate_secret_key(32),
        description="Secret key for encryption. Auto-generated if not provided.",
    )
    SALT: bytes = Field(
        default_factory=lambda: generate_salt(32),
        description="Salt for key strengthening. Auto-generated if not provided.",
    )

    # --- Token Settings ---
    DEFAULT_EXPIRATION_HOURS: int = Field(
        default=24, description="Default token expiration time in hours."
    )


def create_settings_instance(**kwargs) -> Settings:
    """
    Create a settings instance and validate

    Args:
        **kwargs: Optional values likes:
            SECRET_KEY, SALT, DEFAULT_EXPIRATION_HOURS

    Returns:
        Settings: A new settings instance with merged values.

    Raises:
        ValueError: if the settings are invalid
    """
    try:
        settings = Settings(**kwargs)
    except ValidationError as e:
        raise ValueError(f"Invalid settings: {e}") from e

    # Validation calls
    validate_secret_key(settings.SECRET_KEY)
    validate_salt(settings.SALT)
    validate_expires_hours(settings.DEFAULT_EXPIRATION_HOURS)

    return settings
