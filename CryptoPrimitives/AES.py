from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .PRF import PRF

def aes_prf_logic(key: bytes, query: bytes) -> bytes:
    """Direct AES-128 block cipher evaluation (acts as a PRF)."""
    return aes_encrypt_logic(key, query)

def aes_encrypt_logic(key: bytes, block: bytes) -> bytes:
    """Raw AES Encryption of a single 16-byte block."""
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 requires 16-byte key and 16-byte block.")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def aes_decrypt_logic(key: bytes, block: bytes) -> bytes:
    """Raw AES Decryption of a single 16-byte block."""
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 requires 16-byte key and 16-byte block.")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()

# The Foundation Instance
aes_prf = PRF(
    underlying_primitive=None, 
    logic_func=aes_prf_logic, 
    block_size=16
)