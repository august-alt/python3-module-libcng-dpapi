from .cng_dpapi_wrapper import (
    lib,
    ProtectionDescriptor_p,
    free_memory
)
import ctypes

# A custom exception for library-specific errors
class NcryptError(Exception):
    def __init__(self, message, error_code):
        super().__init__(f"{message} (Error Code: {error_code})")
        self.error_code = error_code

def _check_status(status_code, func_name):
    """Helper function to check the return code of a C function."""
    if status_code != 0:
        # Assuming 0 is success, which is a common convention.
        # Your library might use a different convention.
        raise NcryptError(f"Function '{func_name}' failed", status_code)

def _to_c_string(py_string):
    """Converts a Python string or None to a C-compatible bytes object."""
    if py_string is None:
        return None
    return py_string.encode('utf-8')

def create_protection_descriptor(descriptor_string: str, flags: int = 0) -> ProtectionDescriptor_p:
    """
    Creates a protection descriptor handle.

    Args:
        descriptor_string: The string defining the protection rules.
        flags: Flags to modify behavior.

    Returns:
        A handle (opaque pointer) to the protection descriptor.

    Raises:
        NcryptError: If the C function call fails.
    """
    descriptor_p = ProtectionDescriptor_p() # This will hold the output handle

    status = lib.ncrypt_create_protection_descriptor(
        _to_c_string(descriptor_string),
        flags,
        ctypes.byref(descriptor_p) # Pass a pointer to our handle variable
    )
    _check_status(status, 'ncrypt_create_protection_descriptor')

    return descriptor_p

def protect_secret(
    protection_descriptor: ProtectionDescriptor_p,
    data: bytes,
    server: str = None,
    domain: str = None,
    username: str = None
) -> bytes:
    """
    Encrypts data using the provided protection descriptor.

    Args:
        protection_descriptor: The handle from create_protection_descriptor.
        data: The raw bytes to encrypt.
        server, domain, username: Optional context parameters.

    Returns:
        The encrypted data as a bytes object.

    Raises:
        NcryptError: If the C function call fails.
    """
    encrypted_data_p = ctypes.c_void_p()
    encrypted_data_size = ctypes.c_uint32()

    status = lib.ncrypt_protect_secret(
        protection_descriptor,
        data, # ctypes handles bytes -> const char* automatically
        len(data),
        ctypes.byref(encrypted_data_p),
        ctypes.byref(encrypted_data_size),
        _to_c_string(server),
        _to_c_string(domain),
        _to_c_string(username)
    )
    _check_status(status, 'ncrypt_protect_secret')

    try:
        # Copy the C buffer into a Python bytes object
        result = ctypes.string_at(encrypted_data_p, encrypted_data_size.value)
    finally:
        # CRITICAL: Free the memory allocated by the C library
        if encrypted_data_p.value:
            free_memory(encrypted_data_p)            

    return result

def unprotect_secret(
    encrypted_data: bytes,
    server: str = None,
    domain: str = None,
    username: str = None
) -> bytes:
    """
    Decrypts data.

    Args:
        encrypted_data: The encrypted data to decrypt.
        server, domain, username: Optional context parameters.

    Returns:
        The original, decrypted data as a bytes object.

    Raises:
        NcryptError: If the C function call fails.
    """
    unpacked_data_p = ctypes.c_void_p()
    unpacked_data_size = ctypes.c_uint32()

    status = lib.ncrypt_unprotect_secret(
        encrypted_data,
        len(encrypted_data),
        ctypes.byref(unpacked_data_p),
        ctypes.byref(unpacked_data_size),
        _to_c_string(server),
        _to_c_string(domain),
        _to_c_string(username)
    )
    _check_status(status, 'ncrypt_unprotect_secret')

    try:
        # Copy the C buffer into a Python bytes object
        result = ctypes.string_at(unpacked_data_p, unpacked_data_size.value)
    finally:
        # CRITICAL: Free the memory allocated by the C library
        if unpacked_data_p.value:
            free_memory(unpacked_data_p)            

    return result
