# Implementations/PA_4.py

import os
# We assume you have implemented your own AES and exposed these logic functions
# This import will work once your AES.py is complete.
from CryptoPrimitives.AES import aes_encrypt_logic, aes_decrypt_logic
from CryptoPrimitives.PRF import PRF

# --- PRF/PRP Initialization ---
# We create two instances of your PRF class.
# 1. prf_encrypt: Uses your forward AES logic for encryption.
# 2. prf_decrypt: Uses your inverse AES logic for decryption (needed for CBC).
# This assumes your PRF class can wrap both encryption and decryption logic.
prf_encrypt = PRF(underlying_primitive=None, logic_func=aes_encrypt_logic, block_size=16)
prf_decrypt = PRF(underlying_primitive=None, logic_func=aes_decrypt_logic, block_size=16)

BLOCK_SIZE = 16 # AES block size is 16 bytes

def pad(data: bytes) -> bytes:
    """Pads data to be a multiple of BLOCK_SIZE using PKCS#7."""
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(padded_data: bytes) -> bytes:
    """Removes PKCS#7 padding from data."""
    if not isinstance(padded_data, bytes) or not padded_data:
        raise ValueError("Padded data must be a non-empty bytes string.")
    padding_len = padded_data[-1]
    if padding_len > BLOCK_SIZE or padding_len == 0:
        raise ValueError("Invalid padding length.")
    if padded_data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes.")
    return padded_data[:-padding_len]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XORs two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

# 1. CBC Mode
def CBC_Enc(k: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Encrypts a message using CBC mode with your PRF."""
    IV = os.urandom(BLOCK_SIZE)
    padded_M = pad(M)
    
    ciphertext = b''
    prev_block = IV
    
    for i in range(0, len(padded_M), BLOCK_SIZE):
        block = padded_M[i:i+BLOCK_SIZE]
        xored_block = xor_bytes(block, prev_block)
        encrypted_block = prf_encrypt.evaluate(k, xored_block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
        
    return IV, ciphertext

def CBC_Dec(k: bytes, IV: bytes, C: bytes) -> bytes:
    """Decrypts a message using CBC mode with your inverse PRF."""
    plaintext = b''
    prev_block = IV
    
    for i in range(0, len(C), BLOCK_SIZE):
        block = C[i:i+BLOCK_SIZE]
        decrypted_block = prf_decrypt.evaluate(k, block)
        xored_block = xor_bytes(decrypted_block, prev_block)
        plaintext += xored_block
        prev_block = block
        
    return unpad(plaintext)

# 2. OFB Mode
def OFB_Enc_Dec(k: bytes, IV: bytes, data: bytes) -> bytes:
    """Encrypts or decrypts data using OFB mode."""
    keystream = b''
    feedback = IV
    
    # Generate enough keystream to cover the data
    num_blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE
    
    for _ in range(num_blocks):
        feedback = prf_encrypt.evaluate(k, feedback)
        keystream += feedback
        
    # Trim keystream to match data length and XOR
    return xor_bytes(data, keystream[:len(data)])

# 3. Randomized CTR Mode
def CTR_Enc(k: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Encrypts a message using randomized CTR mode."""
    nonce = os.urandom(BLOCK_SIZE // 2)  # 8-byte nonce
    
    num_blocks = (len(M) + BLOCK_SIZE - 1) // BLOCK_SIZE
    
    keystream = b''
    for i in range(num_blocks):
        counter_bytes = i.to_bytes(BLOCK_SIZE // 2, 'big')
        ctr_block_input = nonce + counter_bytes
        keystream += prf_encrypt.evaluate(k, ctr_block_input)
        
    ciphertext = xor_bytes(M, keystream[:len(M)])
    return nonce, ciphertext

def CTR_Dec(k: bytes, nonce: bytes, C: bytes) -> bytes:
    """Decrypts a message using CTR mode."""
    num_blocks = (len(C) + BLOCK_SIZE - 1) // BLOCK_SIZE
    
    keystream = b''
    for i in range(num_blocks):
        counter_bytes = i.to_bytes(BLOCK_SIZE // 2, 'big')
        ctr_block_input = nonce + counter_bytes
        keystream += prf_encrypt.evaluate(k, ctr_block_input)
        
    plaintext = xor_bytes(C, keystream[:len(C)])
    return plaintext

# 5. Attack Demos
def demo_cbc_iv_reuse_attack():
    """Demonstrates the CBC IV reuse attack."""
    print("\n--- Demonstrating CBC IV Reuse Attack ---")
    key = os.urandom(16)
    iv_reuse = os.urandom(BLOCK_SIZE)
    
    # Two messages that share a common block at the end.
    m1 = pad(b"Transaction: Pay $100 to Alice.")
    m2 = pad(b"Transaction: Pay $100 to Bob.  ") # Padded to same length

    # Manually encrypt to force IV reuse
    c1, _ = CBC_Enc_manual(key, m1, iv_reuse)
    c2, _ = CBC_Enc_manual(key, m2, iv_reuse)

    print(f"M1 (hex): {m1.hex()}")
    print(f"M2 (hex): {m2.hex()}")
    print(f"C1 (hex): {c1.hex()}")
    print(f"C2 (hex): {c2.hex()}")

    # Attacker XORs the first blocks of ciphertext to learn info about first plaintext blocks
    c1_block0 = c1[:BLOCK_SIZE]
    c2_block0 = c2[:BLOCK_SIZE]
    p1_xor_p2 = xor_bytes(prf_decrypt.evaluate(key, c1_block0), prf_decrypt.evaluate(key, c2_block0))
    
    print(f"D(C1_0) XOR D(C2_0) = P1_0 XOR P2_0")
    print(f"Recovered XOR of first blocks: {p1_xor_p2.hex()}")
    print(f"Actual XOR of first blocks:  {xor_bytes(m1[:BLOCK_SIZE], m2[:BLOCK_SIZE]).hex()}")
    assert p1_xor_p2 == xor_bytes(m1[:BLOCK_SIZE], m2[:BLOCK_SIZE])
    print("Attack successful: Leaked XOR of plaintext blocks.")

def CBC_Enc_manual(k, M_padded, IV):
    """Helper for attack demo to force IV reuse."""
    # This is a simplified version of CBC_Enc for the demo
    ciphertext = b''
    prev_block = IV
    for i in range(0, len(M_padded), BLOCK_SIZE):
        block = M_padded[i:i+BLOCK_SIZE]
        xored_block = xor_bytes(block, prev_block)
        encrypted_block = prf_encrypt.evaluate(k, xored_block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return ciphertext, IV

def demo_ofb_keystream_reuse_attack():
    """Demonstrates the OFB keystream reuse attack."""
    print("\n--- Demonstrating OFB Keystream Reuse Attack ---")
    key = os.urandom(16)
    iv_reuse = os.urandom(BLOCK_SIZE)
    m1 = b"This is the first secret message."
    m2 = b"This is the second secret message, also secret."

    # Ensure messages are same length for simple XOR demo
    max_len = max(len(m1), len(m2))
    m1 = m1.ljust(max_len, b'\0')
    m2 = m2.ljust(max_len, b'\0')

    c1 = OFB_Enc_Dec(key, iv_reuse, m1)
    c2 = OFB_Enc_Dec(key, iv_reuse, m2)
    
    # Attacker gets C1 and C2, and XORs them
    c1_xor_c2 = xor_bytes(c1, c2)
    m1_xor_m2 = xor_bytes(m1, m2)
    
    print(f"C1 XOR C2 recovers M1 XOR M2: {c1_xor_c2}")
    assert c1_xor_c2 == m1_xor_m2
    print("Attack successful: C1 XOR C2 recovered M1 XOR M2.")

# 6. Correctness Tests
def run_correctness_tests():
    """Runs correctness tests for all modes."""
    print("\n--- Running Correctness Tests ---")
    test_key = os.urandom(16)
    
    messages = {
        "short": b"a",
        "one block": b"16-byte-message!",
        "multi-block": b"This is a much longer message that spans several blocks."
    }
    
    for name, msg in messages.items():
        # CBC Test
        iv_cbc, c_cbc = CBC_Enc(test_key, msg)
        decrypted_cbc = CBC_Dec(test_key, iv_cbc, c_cbc)
        assert decrypted_cbc == msg, f"CBC failed for {name} message"
        
        # OFB Test
        iv_ofb = os.urandom(BLOCK_SIZE)
        c_ofb = OFB_Enc_Dec(test_key, iv_ofb, msg)
        decrypted_ofb = OFB_Enc_Dec(test_key, iv_ofb, c_ofb)
        assert decrypted_ofb == msg, f"OFB failed for {name} message"
        
        # CTR Test
        nonce_ctr, c_ctr = CTR_Enc(test_key, msg)
        decrypted_ctr = CTR_Dec(test_key, nonce_ctr, c_ctr)
        assert decrypted_ctr == msg, f"CTR failed for {name} message"
        
    print("All correctness tests passed!")

if __name__ == '__main__':
    # This block will run when you execute the file directly.
    # It requires your custom AES to be implemented to work without errors.
    try:
        run_correctness_tests()
        demo_cbc_iv_reuse_attack()
        demo_ofb_keystream_reuse_attack()
    except Exception as e:
        print("\nAn error occurred. This is expected if your custom AES is not yet implemented.")
        print(f"Error: {e}")
