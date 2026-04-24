# Implementations/PA_12.py

import os
import random

# Import Miller-Rabin primality test from PA#13
from Implementations.PA_13 import is_prime

# =====================================================================
# 1. Math Utilities (No library pow)
# =====================================================================

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation using Square-and-Multiply."""
    res = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return res

def extended_gcd(a: int, b: int):
    """Extended Euclidean Algorithm. Returns (gcd, x, y)."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a: int, m: int) -> int:
    """Computes modular inverse using Extended Euclidean Algorithm."""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return x % m

def generate_prime(bits: int) -> int:
    """Generates a prime number of the specified bit length."""
    while True:
        # Generate random odd number with high and low bits set
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

# =====================================================================
# 2. Key Generation
# =====================================================================

def rsa_keygen(bits: int = 1024):
    """
    Generates RSA public and private keys.
    Returns: pk=(N, e), sk=(N, d, p, q, dp, dq, q_inv)
    """
    prime_bits = bits // 2
    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)
    while p == q:
        q = generate_prime(prime_bits)
        
    N = p * q
    phi_N = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi_N)
    
    # CRT parameters for PA#14
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)
    
    pk = (N, e)
    sk = (N, d, p, q, dp, dq, q_inv)
    return pk, sk

# =====================================================================
# 3. Textbook RSA
# =====================================================================

def rsa_enc(pk: tuple, m: int) -> int:
    """Textbook RSA Encryption: C = M^e mod N"""
    N, e = pk
    if m >= N or m < 0:
        raise ValueError("Message integer must be in range [0, N-1]")
    return mod_exp(m, e, N)

def rsa_dec(sk: tuple, c: int) -> int:
    """Textbook RSA Decryption: M = C^d mod N"""
    N, d = sk[:2]
    return mod_exp(c, d, N)

# =====================================================================
# 4. PKCS#1 v1.5 Padding & Wrapper
# =====================================================================

def pkcs15_enc(pk: tuple, m: bytes) -> bytes:
    """PKCS#1 v1.5 RSA Encryption"""
    N, e = pk
    k = (N.bit_length() + 7) // 8  # Byte length of modulus
    
    if len(m) > k - 11:
        raise ValueError("Message too long for this RSA key size.")
        
    # Generate padding: >= 8 bytes of non-zero random values
    ps_len = k - len(m) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        rand_byte = os.urandom(1)
        if rand_byte != b'\x00':
            ps.extend(rand_byte)
            
    # EM = 0x00 || 0x02 || PS || 0x00 || M
    em = b'\x00\x02' + bytes(ps) + b'\x00' + m
    
    m_int = int.from_bytes(em, 'big')
    c_int = rsa_enc(pk, m_int)
    
    return c_int.to_bytes(k, 'big')

def pkcs15_dec(sk: tuple, c: bytes) -> bytes:
    """PKCS#1 v1.5 RSA Decryption (Returns None/⊥ on invalid padding)"""
    N, d = sk[:2]
    k = (N.bit_length() + 7) // 8
    
    if len(c) != k:
        return None # ⊥
        
    c_int = int.from_bytes(c, 'big')
    m_int = rsa_dec(sk, c_int)
    em = m_int.to_bytes(k, 'big')
    
    # Validation: Check 0x00 0x02 header
    if len(em) < 11 or em[0] != 0x00 or em[1] != 0x02:
        return None # ⊥
        
    # Find the 0x00 separator
    try:
        sep_index = em.index(b'\x00', 2)
    except ValueError:
        return None # ⊥ (No separator found)
        
    # Validation: PS must be at least 8 bytes long
    if sep_index - 2 < 8:
        return None # ⊥
        
    return em[sep_index + 1:]

# =====================================================================
# 5. Attack Demos
# =====================================================================

def demo_determinism_attack():
    print("\n--- Textbook RSA Determinism Attack ---")
    pk, sk = rsa_keygen(512)
    vote = b"Vote: Yes"
    vote_int = int.from_bytes(vote, 'big')
    
    # Textbook
    c1 = rsa_enc(pk, vote_int)
    c2 = rsa_enc(pk, vote_int)
    print(f"Textbook RSA C1 == C2: {c1 == c2} (Leaked Information!)")
    
    # PKCS#1 v1.5
    c3 = pkcs15_enc(pk, vote)
    c4 = pkcs15_enc(pk, vote)
    print(f"PKCS#1 v1.5 C3 == C4: {c3 == c4} (CPA Secure against this attack)")

class ToyBleichenbacherOracle:
    def __init__(self, sk):
        self.sk = sk
        self.k = (sk[0].bit_length() + 7) // 8
        
    def validate_padding(self, c_int: int) -> bool:
        """Returns True if ciphertext decrypts to a PKCS#1 v1.5 conforming block."""
        m_int = rsa_dec(self.sk, c_int)
        em = m_int.to_bytes(self.k, 'big')
        return len(em) >= 2 and em[0] == 0x00 and em[1] == 0x02

def demo_bleichenbacher_toy():
    print("\n--- Toy Bleichenbacher Padding Oracle (Step 1) ---")
    # Small keysize to make the toy demo fast
    pk, sk = rsa_keygen(256) 
    N, e = pk
    oracle = ToyBleichenbacherOracle(sk)
    
    msg = b"Hi"
    c_bytes = pkcs15_enc(pk, msg)
    c_original = int.from_bytes(c_bytes, 'big')
    
    print("[*] Original ciphertext is PKCS conforming:", oracle.validate_padding(c_original))
    
    print("[*] Attacker searching for multiplier 's' to create a new valid padding...")
    # Step 1 of Bleichenbacher: Blinding. Find s_1 such that (c * s_1^e) is PKCS conforming
    s = 2 
    max_tries = 50000
    found = False
    
    for _ in range(max_tries):
        # c' = c * s^e mod N
        c_prime = (c_original * mod_exp(s, e, N)) % N
        if oracle.validate_padding(c_prime):
            print(f"[+] SUCCESS: Found valid multiplier s = {s}")
            print(f"    The attacker now knows the first 16 bits of (m * {s} mod N) are 0x0002!")
            print("    This severely narrows down the mathematical bounds of the original message 'm'.")
            print("    (Full Bleichenbacher repeats this to shrink the bounds until 'm' is recovered).")
            found = True
            break
        s += 1
        
    if not found:
        print(f"[-] Could not find 's' within {max_tries} tries (Normal, usually takes more computing).")

if __name__ == "__main__":
    demo_determinism_attack()
    demo_bleichenbacher_toy()