import ctypes
import platform

# --- Helper to load the shared library ---
# The user needs to replace 'libncrypt' with the actual name of the compiled C library.
# For example:
# - on Linux: 'libncrypt.so'
# - on macOS: 'libncrypt.dylib'
# - on Windows: 'ncrypt.dll'
lib_name = 'libcng-dpapi.so.0'
if platform.system() == 'Windows':
    lib_name = 'ncrypt.dll'
elif platform.system() == 'Darwin': # macOS
    lib_name = 'libncrypt.dylib'

try:
    # Use CDLL for libraries using the standard cdecl calling convention
    lib = ctypes.CDLL(lib_name)
except OSError as e:
    print(f"Error: Could not load the shared library '{lib_name}'.")
    print("Please ensure the library is in a searchable path (e.g., LD_LIBRARY_PATH, PATH, or the current directory).")
    print(f"Original error: {e}")
    # We create a dummy object so the script can be imported, but it will fail on use.
    class DummyLib:
        def __getattr__(self, name):
            raise RuntimeError(f"The '{lib_name}' library is not loaded.")
    lib = DummyLib()


# --- C Type Definitions ---

# From <stdint.h>
c_uint8_p = ctypes.POINTER(ctypes.c_ubyte)
c_uint32_p = ctypes.POINTER(ctypes.c_uint32)

# typedef struct ProtectionDescriptor *ProtectionDescriptor_p;
# This is an opaque pointer/handle. We represent it with c_void_p.
ProtectionDescriptor_p = ctypes.c_void_p

# This will represent the pointer-to-pointer types for output buffers
# e.g., uint8_t **unpacked_data
c_void_p_p = ctypes.POINTER(ctypes.c_void_p)


# --- C Function Prototypes ---

# uint32_t
# ncrypt_create_protection_descriptor(const char *desciptor_string,
#                                     uint32_t flags,
#                                     ProtectionDescriptor_p *desciptor);
try:
    lib.ncrypt_create_protection_descriptor.restype = ctypes.c_uint32
    lib.ncrypt_create_protection_descriptor.argtypes = [
        ctypes.c_char_p,                  # const char *desciptor_string
        ctypes.c_uint32,                  # uint32_t flags
        ctypes.POINTER(ProtectionDescriptor_p) # ProtectionDescriptor_p *desciptor (output)
    ]
except AttributeError:
    pass # Library not loaded, ignore.

# uint32_t
# ncrypt_unprotect_secret(const uint8_t* data,
#                         const uint32_t data_size,
#                         uint8_t **unpacked_data,
#                         uint32_t *unpacked_data_size,
#                         const char* server,
#                         const char *domain,
#                         const char* username);
try:
    lib.ncrypt_unprotect_secret.restype = ctypes.c_uint32
    lib.ncrypt_unprotect_secret.argtypes = [
        ctypes.c_char_p,                  # const uint8_t* data (input buffer)
        ctypes.c_uint32,                  # const uint32_t data_size
        c_void_p_p,                       # uint8_t **unpacked_data (output)
        c_uint32_p,                       # uint32_t *unpacked_data_size (output)
        ctypes.c_char_p,                  # const char* server
        ctypes.c_char_p,                  # const char* domain
        ctypes.c_char_p                   # const char* username
    ]
except AttributeError:
    pass # Library not loaded, ignore.

# uint32_t
# ncrypt_protect_secret(const ProtectionDescriptor_p protection_descriptor,
#                       const uint8_t* data,
#                       const uint32_t data_size,
#                       uint8_t **encrypted_data,
#                       uint32_t *encrypted_data_size,
#                       const char* server,
#                       const char* domain,
#                       const char* username);
try:
    lib.ncrypt_protect_secret.restype = ctypes.c_uint32
    lib.ncrypt_protect_secret.argtypes = [
        ProtectionDescriptor_p,           # const ProtectionDescriptor_p protection_descriptor
        ctypes.c_char_p,                  # const uint8_t* data (input buffer)
        ctypes.c_uint32,                  # const uint32_t data_size
        c_void_p_p,                       # uint8_t **encrypted_data (output)
        c_uint32_p,                       # uint32_t *encrypted_data_size (output)
        ctypes.c_char_p,                  # const char* server
        ctypes.c_char_p,                  # const char* domain
        ctypes.c_char_p                   # const char* username
    ]
except AttributeError:
    pass # Library not loaded, ignore.

try:
    # On Linux/macOS, libc is loaded implicitly. On Windows, you might need to load it.
    if platform.system() == 'Windows':
        c_lib = ctypes.CDLL('msvcrt')
    else:
        # On POSIX systems, find_library can locate libc.
        from ctypes.util import find_library
        libc_path = find_library('c')
        c_lib = ctypes.CDLL(libc_path)

    c_lib.free.argtypes = [ctypes.c_void_p]
    c_lib.free.restype = None
    free_memory = c_lib.free
except (OSError, AttributeError):
    print("Warning: Could not bind the standard C 'free' function. Memory leaks will occur.")
    def free_memory(ptr):
        print(f"Warning: 'free' not available. Memory at {ptr} is not being freed.")
