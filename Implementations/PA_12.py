# Implementations/PA_12.py

import os
import math

try:
    from Implementations.PA_13 import gen_prime, square_and_multiply
except ImportError:
    try:
        from PA_13 import gen_prime, square_and_multiply
    except ImportError:
        import sys
        sys.exit("[!] Fatal: Could not import PA_13. Ensure gen_prime and square_and_multiply are available.")

# =====================================================================
# 1. NUMBER THEORY UTILITIES (No-Library Rule)
# =====================================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a: int, m: int) -> int:
    """Computes the modular inverse of a mod m."""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return x % m

# =====================================================================
# 2. RSA KEY GENERATION
# =====================================================================

def rsa_keygen(bits: int = 1024, fixed_e: int = 65537) -> tuple[dict, dict]:
    """
    Generates RSA public and private keys.
    Returns (sk, pk) where sk contains CRT parameters for PA#14.
    """
    prime_size = bits // 2
    
    e = fixed_e
    
    # 1. Generate two distinct large primes such that (p-1) and (q-1) are coprime to e
    while True:
        p = gen_prime(prime_size)
        if math.gcd(e, p - 1) == 1:
            break
            
    while True:
        q = gen_prime(prime_size)
        if p != q and math.gcd(e, q - 1) == 1:
            break
        
    # 2. Compute Modulus and Totient
    N = p * q
    phi = (p - 1) * (q - 1)
    
    # 3. Check coprime condition (guaranteed by the loops above)
    if math.gcd(e, phi) != 1:
        raise ValueError("e and phi(N) are not coprime. Choose a different e.")
        
    # 4. Compute private exponent d
    d = mod_inverse(e, phi)
    
    # 5. Compute CRT parameters (Required for PA#14 Garner's Algorithm)
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    q_inv = mod_inverse(q, p)
    
    sk = {
        'N': N, 'd': d, 'p': p, 'q': q, 
        'd_p': d_p, 'd_q': d_q, 'q_inv': q_inv
    }
    pk = {'N': N, 'e': e}
    
    return sk, pk

# =====================================================================
# 3. TEXTBOOK RSA (Insecure)
# =====================================================================

def rsa_enc(pk: dict, m: int) -> int:
    """C = M^e mod N"""
    if m >= pk['N']:
        raise ValueError("Message integer is larger than the RSA modulus!")
    return square_and_multiply(m, pk['e'], pk['N'])

def rsa_dec(sk: dict, c: int) -> int:
    """M = C^d mod N"""
    return square_and_multiply(c, sk['d'], sk['N'])

# =====================================================================
# 4. PKCS#1 v1.5 PADDED RSA (Secure against CPA)
# =====================================================================

def pkcs15_enc(pk: dict, m: bytes) -> int:
    """
    Applies PKCS#1 v1.5 padding and encrypts.
    EM = 0x00 || 0x02 || PS || 0x00 || M
    """
    k = (pk['N'].bit_length() + 7) // 8
    
    if len(m) > k - 11:
        raise ValueError(f"Message too long. Max {k - 11} bytes for a {k * 8}-bit key.")
        
    ps_len = k - 3 - len(m)
    
    # Generate random NON-ZERO padding bytes
    ps = bytearray()
    while len(ps) < ps_len:
        rand_byte = os.urandom(1)
        if rand_byte != b'\x00':
            ps.extend(rand_byte)
            
    em = b'\x00\x02' + bytes(ps) + b'\x00' + m
    m_int = int.from_bytes(em, 'big')
    
    return rsa_enc(pk, m_int)

def pkcs15_dec(sk: dict, c: int) -> bytes:
    """
    Decrypts textbook RSA, then validates and strips PKCS#1 v1.5 padding.
    Returns None if padding is malformed (this protects against some attacks, 
    but creates the padding oracle if not constant-time).
    """
    k = (sk['N'].bit_length() + 7) // 8
    
    m_int = rsa_dec(sk, c)
    # Convert integer back to bytes, enforcing the modulus byte size
    em = m_int.to_bytes(k, 'big')
    
    # Validate Header
    if em[0] != 0x00 or em[1] != 0x02:
        return None # Malformed padding
        
    # Find the 0x00 separator
    separator_idx = -1
    for i in range(2, k):
        if em[i] == 0x00:
            separator_idx = i
            break
            
    if separator_idx == -1 or separator_idx < 10:
        # Separator not found, or PS is less than 8 bytes long
        return None
        
    return em[separator_idx + 1:]

# =====================================================================
# 5. DEMOS AND ATTACKS
# =====================================================================

def demo_determinism():
    """Demonstrates why Textbook RSA is not CPA-Secure."""
    print("\n--- Textbook RSA Determinism Demo ---")
    
    # We use a very small key for speed in the demo
    print("[*] Generating 512-bit RSA Keys...")
    sk, pk = rsa_keygen(512)
    
    vote = b"VOTE_YES"
    m_int = int.from_bytes(vote, 'big')
    
    print(f"[*] Simulating a ballot system encrypting: {vote}")
    
    c1_textbook = rsa_enc(pk, m_int)
    c2_textbook = rsa_enc(pk, m_int)
    
    print("\n[Textbook RSA]")
    print(f"  Ciphertext 1: {hex(c1_textbook)[:30]}...")
    print(f"  Ciphertext 2: {hex(c2_textbook)[:30]}...")
    if c1_textbook == c2_textbook:
        print("  [!] FAILURE: Ciphertexts are identical. An eavesdropper knows the vote is the same.")
        
    print("\n[PKCS#1 v1.5 RSA]")
    c1_padded = pkcs15_enc(pk, vote)
    c2_padded = pkcs15_enc(pk, vote)
    print(f"  Ciphertext 1: {hex(c1_padded)[:30]}...")
    print(f"  Ciphertext 2: {hex(c2_padded)[:30]}...")
    if c1_padded != c2_padded:
        print("  [+] SUCCESS: Ciphertexts are completely different due to random padding.")


def demo_bleichenbacher_toy():
    """
    A simplified padding oracle demonstration.
    Shows how an attacker can use server error messages to multiply 
    the ciphertext and find conforming padding structures.
    """
    print("\n--- Bleichenbacher Padding Oracle (Simplified Demo) ---")
    sk, pk = rsa_keygen(512)
    N, e = pk['N'], pk['e']
    k = (N.bit_length() + 7) // 8
    
    # 1. The Oracle
    def padding_oracle(ciphertext: int) -> bool:
        """Returns True if the decrypted ciphertext starts with 00 02."""
        plaintext_int = rsa_dec(sk, ciphertext)
        em = plaintext_int.to_bytes(k, 'big')
        return em[0] == 0x00 and em[1] == 0x02

    # 2. The Target
    secret_msg = b"SECRET"
    c_target = pkcs15_enc(pk, secret_msg)
    
    print("[*] Eavesdropped a PKCS#1 v1.5 ciphertext.")
    print("[*] Sending manipulated ciphertexts to the oracle to find a mathematical multiplier (s_1)...")
    
    # 3. The Attack: Finding s_1 (Step 2a of Bleichenbacher)
    # We look for a multiplier s_1 such that (c_target * s_1^e) mod N is PKCS conforming.
    # This proves the oracle leaks mathematical relationships about the plaintext.
    
    B = 2 ** (8 * (k - 2))
    s_1 = (N // (3 * B)) # Starting threshold recommended by the paper
    
    attempts = 0
    while True:
        attempts += 1
        
        # c' = c * s^e mod N
        c_prime = (c_target * square_and_multiply(s_1, e, N)) % N
        
        if padding_oracle(c_prime):
            print(f"[!] Vulnerability Confirmed!")
            print(f"    Found conforming multiplier s_1 = {s_1} after {attempts} oracle queries.")
            print("    The attacker now knows that (m * s_1) mod N falls within the strict 00 02 bounds.")
            print("    (Full Bleichenbacher would narrow the intervals until m is recovered).")
            break
            
        s_1 += 1
        if attempts > 5000:
            print("[-] Demo timeout (interval gap too large for quick simulation).")
            break


if __name__ == "__main__":
    demo_determinism()
    demo_bleichenbacher_toy()