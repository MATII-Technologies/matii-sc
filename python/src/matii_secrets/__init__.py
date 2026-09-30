"""Client for the Matii Secret Service."""

from .client import (
    ApiError,
    Client,
    DynamicLease,
    Secret,
    file_jwt,
    oidc_token_source,
    static_token,
    to_dict,
    to_dotenv,
)
from .crypto import DecryptError, decrypt_asymmetric, encrypt_asymmetric, key_digest, parse_token

__all__ = [
    "ApiError", "Client", "DecryptError", "DynamicLease", "Secret", "decrypt_asymmetric", "encrypt_asymmetric",
    "file_jwt", "key_digest", "oidc_token_source", "parse_token", "static_token", "to_dict", "to_dotenv",
]
__version__ = "0.1.0"
