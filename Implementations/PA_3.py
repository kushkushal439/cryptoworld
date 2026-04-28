import os
import random

from CryptoPrimitives.PRF import PRF
# Using the AES-based PRF wrapped in out CryptoPrimitives for practical execution,
# as the GGM PRF (from PA#2) operates bit-by-bit and is too slow for multi-block encryption.
from CryptoPrimitives.AES import aes_prf

BLOCK_SIZE = 16

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of the same length."""
    return bytes(x ^ y for x, y in zip(a, b))

def Enc(k: bytes, m: bytes, prf_instance: PRF = aes_prf) -> tuple[bytes, bytes]:
    """
    CPA-secure encryption scheme: C = <r, F_k(r) XOR m>
    Counter-based extension for multi-block messages: applies PRF to r, r+1, r+2...
    r is freshly sampled each call.
    """
    # Sample r uniformly at random
    r_int = random.getrandbits(BLOCK_SIZE * 8)
    r_bytes = r_int.to_bytes(BLOCK_SIZE, 'big')

    num_blocks = (len(m) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if num_blocks == 0:
        num_blocks = 1
        
    keystream = b''
    for i in range(num_blocks):
        current_r = (r_int + i) % (1 << (BLOCK_SIZE * 8))
        current_r_bytes = current_r.to_bytes(BLOCK_SIZE, 'big')
        
        keystream_block = prf_instance.evaluate(key=k, query=current_r_bytes)
        keystream += keystream_block
        
    # Truncating keystream to message length naturally handles any unaligned padding
    c = xor_bytes(m, keystream[:len(m)])
    return r_bytes, c

def Dec(k: bytes, r: bytes, c: bytes, prf_instance: PRF = aes_prf) -> bytes:
    """
    Decryption: m = F_k(r) XOR c
    """
    r_int = int.from_bytes(r, 'big')
    
    num_blocks = (len(c) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if num_blocks == 0:
        num_blocks = 1
        
    keystream = b''
    for i in range(num_blocks):
        current_r = (r_int + i) % (1 << (BLOCK_SIZE * 8))
        current_r_bytes = current_r.to_bytes(BLOCK_SIZE, 'big')
        
        keystream_block = prf_instance.evaluate(key=k, query=current_r_bytes)
        keystream += keystream_block
        
    m = xor_bytes(c, keystream[:len(c)])
    return m

def Enc_broken(k: bytes, m: bytes, fixed_r: bytes, prf_instance: PRF = aes_prf) -> tuple[bytes, bytes]:
    """
    Broken variant that reuses r (deterministic encryption).
    """
    r_int = int.from_bytes(fixed_r, 'big')
    num_blocks = (len(m) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if num_blocks == 0:
        num_blocks = 1
        
    keystream = b''
    for i in range(num_blocks):
        current_r = (r_int + i) % (1 << (BLOCK_SIZE * 8))
        current_r_bytes = current_r.to_bytes(BLOCK_SIZE, 'big')
        keystream_block = prf_instance.evaluate(key=k, query=current_r_bytes)
        keystream += keystream_block
        
    c = xor_bytes(m, keystream[:len(m)])
    return fixed_r, c


def ind_cpa_game_simulation():
    """
    Implement the IND-CPA game. Run it with a dummy adversary that queries 
    the encryption oracle 50 times and then attempts to distinguish.
    """
    print("\n--- IND-CPA Game Simulation ---")
    k = os.urandom(16)
    
    def encryption_oracle(message: bytes):
        return Enc(k, message)
        
    print("Dummy adversary queries the encryption oracle 50 times...")
    for _ in range(50):
        msg = os.urandom(random.randint(1, 64))
        encryption_oracle(msg)
        
    # Challenge phase
    m0 = b"Attack at dawn!"
    m1 = b"Attack at dusk!"
    
    b = random.choice([0, 1])
    mb = m0 if b == 0 else m1
    r_challenge, c_challenge = encryption_oracle(mb)
    
    # Dummy adversary has no logic to distinguish, it just guesses randomly.
    # Realistically, an advantage of ~0 is expected.
    guess_b = random.choice([0, 1])
    
    print(f"Adversary guessed: {guess_b}, Actual: {b}")
    print("Advantage is ~0 since the adversary has no information about the message.")

def broken_variant_demonstration():
    """
    Demonstrate the attack on the broken variant that reuses r.
    Queries two equal messages and detects identical ciphertexts.
    """
    print("\n--- Broken Variant Demonstration ---")
    k = os.urandom(16)
    fixed_r = os.urandom(16)
    
    m0 = b"Secret message A"
    m1 = b"Secret message B"
    
    # The adversary queries m0
    _, c_query = Enc_broken(k, m0, fixed_r)
    
    # Challenge phase
    b = random.choice([0, 1])
    mb = m0 if b == 0 else m1
    _, c_challenge = Enc_broken(k, mb, fixed_r)
    
    # Adversary logic: it queried m0 before. If the challenge ciphertext matches the query ciphertext,
    # then the encrypted message must be m0 (since the scheme is deterministic).
    if c_challenge == c_query:
        guess_b = 0
    else:
        guess_b = 1
        
    print(f"Adversary guessed: {guess_b}, Actual: {b}")
    assert guess_b == b
    print("Attack Successful! Reusing 'r' results in deterministic encryption, breaking CPA security.")

if __name__ == "__main__":
    message = b"This is a test message for PA#3 to verify correctness, spanning multiple blocks!"
    key = os.urandom(16)
    
    r, c = Enc(key, message)
    print("Ciphertext:", c.hex())
    decrypted = Dec(key, r, c)
    assert decrypted == message
    print("\nEncryption/Decryption correctness test passed!")
    
    ind_cpa_game_simulation()
    broken_variant_demonstration()

class CPA_Scheme:
    def __init__(self):
        self.default_key = os.urandom(16)
        
    def encrypt(self, *args):
        """Supports either encrypt(k, m) or encrypt(m)"""
        if len(args) == 2:
            return Enc(args[0], args[1])
        elif len(args) == 1:
            return Enc(self.default_key, args[0])
        else:
            raise ValueError("Expected 1 or 2 arguments.")
            
    def decrypt(self, *args):
        """Supports either decrypt(k, r, c) or decrypt(r, c)"""
        if len(args) == 3:
            return Dec(args[0], args[1], args[2])
        elif len(args) == 2:
            return Dec(self.default_key, args[0], args[1])
        else:
            raise ValueError("Expected 2 or 3 arguments.")

