# Implementations/PA_14.py

import time
import math

try:
    from Implementations.PA_12 import rsa_keygen, rsa_enc, rsa_dec, pkcs15_enc
except ImportError:
    try:
        from PA_12 import rsa_keygen, rsa_enc, rsa_dec, pkcs15_enc
    except ImportError:
        import sys
        sys.exit("[!] Fatal: Could not import PA_12. Ensure rsa_keygen, rsa_enc, rsa_dec, and pkcs15_enc are available.")

# =====================================================================
# 1. MATH UTILITIES (CRT & Mod Inverse)
# =====================================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm."""
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

def crt(residues: list[int], moduli: list[int]) -> int:
    """
    Chinese Remainder Theorem Solver.
    Takes a list of residues (a_i) and pairwise coprime moduli (n_i).
    Returns the unique x mod N.
    """
    total_N = 1
    for n in moduli:
        total_N *= n
        
    x = 0
    for a_i, n_i in zip(residues, moduli):
        M_i = total_N // n_i
        M_i_inv = mod_inverse(M_i, n_i)
        x = (x + a_i * M_i * M_i_inv) % total_N
        
    return x

def integer_nth_root(y: int, n: int) -> int:
    """
    Computes the integer n-th root of y using Newton's method.
    Required for Håstad's broadcast attack.
    """
    if y < 0:
        raise ValueError("Cannot compute root of negative number.")
    if y == 0:
        return 0
        
    # Initial guess
    x = y
    while True:
        step = ((n - 1) * x + y // (x ** (n - 1))) // n
        if step >= x:
            return x
        x = step

# =====================================================================
# 2. CRT-BASED RSA DECRYPTION (Garner's Algorithm)
# =====================================================================

def rsa_dec_crt(sk: dict, c: int) -> int:
    """
    Decrypts an RSA ciphertext using Garner's algorithm for a ~4x speedup.
    sk dictionary must contain: p, q, d_p, d_q, q_inv
    """
    p = sk['p']
    q = sk['q']
    d_p = sk['d_p']
    d_q = sk['d_q']
    q_inv = sk['q_inv']
    
    # 1. Partial exponentiations
    m_p = pow(c, d_p, p)
    m_q = pow(c, d_q, q)
    
    # 2. Garner's Recombination
    h = (q_inv * (m_p - m_q)) % p
    m = m_q + h * q
    return m

def benchmark_rsa_decryption():
    """Compares standard textbook RSA decryption vs CRT-based decryption."""
    import random
    
    print("\n--- 1. Correctness Verification (Point 2) ---")
    sk, pk = rsa_keygen(1024)
    print("[*] Verifying rsa_dec_crt == rsa_dec for 100 random messages...")
    for _ in range(100):
        m = random.randrange(2, pk['N'] - 1)
        c = rsa_enc(pk, m)
        assert rsa_dec(sk, c) == rsa_dec_crt(sk, c), "Mismatch in decryption!"
    print("[+] Correctness verified! Garner's algorithm matches standard decryption perfectly.")

    print("\n--- 2. Performance Benchmarks (Point 3) ---")
    # To save time if 2048 is too slow, you can reduce the ops count for 2048.
    for bits in [1024, 2048]:
        print(f"\n[*] Generating {bits}-bit keys for benchmark...")
        sk_bench, pk_bench = rsa_keygen(bits)
        
        ops = 1000 if bits == 1024 else 200 # Lower ops for 2048-bit to prevent long hangs in pure Python
        messages = [random.randrange(2, pk_bench['N'] - 1) for _ in range(ops)]
        ciphertexts = [rsa_enc(pk_bench, m) for m in messages]
        
        # Benchmark Standard
        start = time.time()
        for c in ciphertexts:
            rsa_dec(sk_bench, c)
        standard_time = time.time() - start
        
        # Benchmark CRT
        start = time.time()
        for c in ciphertexts:
            rsa_dec_crt(sk_bench, c)
        crt_time = time.time() - start
        
        print(f"[{bits}-bit] Standard Decryption ({ops} ops): {standard_time:.4f} seconds")
        print(f"[{bits}-bit] CRT Decryption ({ops} ops):      {crt_time:.4f} seconds")
        print(f"[{bits}-bit] Speedup Ratio:                 {standard_time / crt_time:.2f}x")

# =====================================================================
# 3. HÅSTAD'S BROADCAST ATTACK
# =====================================================================

def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    """
    Executes Håstad's Broadcast Attack against textbook RSA.
    Given e ciphertexts encrypted under e different moduli with the same e,
    recovers the plaintext m.
    """
    # 1. Use CRT to find m^e mod (N_1 * N_2 * ... * N_e)
    m_pow_e = crt(ciphertexts, moduli)
    
    # 2. Because m < N_i, m^e < product(N_i). 
    # Therefore, the modular result is the exact integer m^e.
    # Take the exact integer e-th root.
    m = integer_nth_root(m_pow_e, e)
    return m

def demo_hastad_attack():
    """Demonstrates breaking textbook RSA and how PKCS#1 v1.5 defeats it."""
    print("\n--- 3. Håstad's Broadcast Attack Demo (e=3) ---")
    
    e = 3
    keys = [rsa_keygen(1024, fixed_e=e) for _ in range(3)]
    moduli = [pk['N'] for sk, pk in keys]
    
    secret_bytes = b"SECRET_BROADCAST_MESSAGE"
    m = int.from_bytes(secret_bytes, 'big')
    
    print(f"[*] Original Secret Message: {m}")
    print(f"    (Byte length: {m.bit_length() // 8} bytes)")
    
    print("\n[*] Scenario 1: Broadcasting with Textbook RSA")
    ciphertexts = [rsa_enc(keys[i][1], m) for i in range(3)]
    
    recovered_m = hastad_attack(ciphertexts, moduli, e)
    if recovered_m == m:
        print("[+] SUCCESS: Textbook RSA is completely broken by CRT!")
        
    print("\n[*] Scenario 2: Attack Boundary (Point 5)")
    # Calculate the exact byte boundary for 3x 1024-bit moduli
    product_N = moduli[0] * moduli[1] * moduli[2]
    max_m_bits = product_N.bit_length() // 3
    max_m_bytes = max_m_bits // 8
    print(f"    Max message length for these three 1024-bit moduli is: {max_m_bytes} bytes.")
    print("    Why? Because N1 * N2 * N3 is approx 3072 bits.")
    print("    If m^3 >= N1 * N2 * N3, the result wraps around the modulo,")
    print("    and the integer cube root will no longer yield the correct m.")

    print("\n[*] Scenario 3: Broadcasting with PKCS#1 v1.5 Padding (Point 6)")
    try:
        # Crucial fix: passing 'secret_bytes' instead of 'm' so len() works in PKCS padding
        padded_ciphertexts = [pkcs15_enc(keys[i][1], secret_bytes) for i in range(3)]
        recovered_padded = hastad_attack(padded_ciphertexts, moduli, e)
        print(f"[-] Recovered Garbage: {recovered_padded}")
        print("    -> FAILED: Padding injects random bytes. The 3 ciphertexts no longer")
        print("       encrypt the *exact* same padded string, destroying the CRT math.")
    except Exception as ex:
        print(f"[-] Attack crashed/failed gracefully as expected: {ex}")

if __name__ == "__main__":
    benchmark_rsa_decryption()
    demo_hastad_attack()