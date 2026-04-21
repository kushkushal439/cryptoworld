from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .PRF import PRF

def aes_prf_logic(key: bytes, query: bytes) -> bytes:
    """
    Direct AES-128 block cipher evaluation.
    Acts as a secure PRF for a single 16-byte block.
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires exactly a 16-byte key, got {len(key)} bytes.")
    
    if len(query) != 16:
        raise ValueError(f"Raw AES evaluation requires exactly a 16-byte query, got {len(query)} bytes.")

    # ECB mode on a single block is mathematically equivalent to the raw AES permutation
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Return the evaluated block
    return encryptor.update(query) + encryptor.finalize()

# ---------------------------------------------------------
# The Foundation Instance
# ---------------------------------------------------------
# This instance can be imported and passed around your project
# whenever a concrete PRF foundation is needed.

aes_prf = PRF(
    underlying_primitive=None, 
    logic_func=aes_prf_logic, 
    block_size=16
)