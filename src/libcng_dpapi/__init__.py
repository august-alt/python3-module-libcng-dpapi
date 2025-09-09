from .cng_dpapi_wrapper import (
    create_protection_descriptor,
    protect_secret,
    unprotect_secret,
    NcryptError
)

__all__ = [
    "NcryptError",
    "create_protection_descriptor",
    "protect_secret",
    "unprotect_secret"
]
