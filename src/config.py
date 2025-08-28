import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
dotenv_path = Path(__file__).resolve().parents[1] / '.env'
load_dotenv(dotenv_path=dotenv_path)

# --- Security ---
# Secret key for encryption. It's recommended to use a long, random string.
# Generate one with: openssl rand -hex 32
SECRET_KEY = os.getenv('SECRET_KEY')

# Salt for key strengthening. Should be a fixed value for the application.
SALT = os.getenv('SALT', 'secure_token_salt_2024').encode('utf-8')

# --- Token Settings ---
# Default token expiration time in hours
DEFAULT_EXPIRATION_HOURS = int(os.getenv('DEFAULT_EXPIRATION_HOURS', 24))

# Maximum number of active tokens allowed per user
MAX_TOKENS_PER_USER = int(os.getenv('MAX_TOKENS_PER_USER', 10))

# --- Logging ---
# Log level for the application (e.g., DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
