from pydantic import Field
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

    # --- Validation ---
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        validate_secret_key(self.SECRET_KEY)
        validate_salt(self.SALT)
        validate_expires_hours(self.DEFAULT_EXPIRATION_HOURS)
