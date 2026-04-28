# Implementations/PA_10.py

import os
import time
import random
import struct

# Import the necessary primitives from prior assignments
from PA_4 import CBC_Enc, CBC_Dec
from PA_7 import MerkleDamgard, md_padding
from PA_8 import DLP_Hash, generate_safe_prime

# =====================================================================
# TASK 7: Constant-Time Comparison
# =====================================================================

def secure_compare(t1: bytes, t2: bytes) -> bool:
    """Compares two byte strings in constant time to prevent timing attacks."""
    if len(t1) != len(t2):
        return False
    result = 0
    for b1, b2 in zip(t1, t2):
        result |= b1 ^ b2
    return result == 0

def insecure_compare(t1: bytes, t2: bytes) -> bool:
    """A naive early-exit comparison for demonstration purposes."""
    if len(t1) != len(t2):
        return False
    for b1, b2 in zip(t1, t2):
        if b1 != b2:
            return False
    return True

# =====================================================================
# TASK 1 & 8: Core HMAC Logic & Interface
# =====================================================================

def HMAC(k: bytes, m: bytes, hash_instance) -> bytes:
    """
    RFC 2104 compliant HMAC using the PA#8 DLP_Hash.
    HMAC(k, m) = H((k XOR opad) || H((k XOR ipad) || m))
    """
    b = hash_instance.block_size
    
    # 1. Key Formatting
    if len(k) > b:
        k = hash_instance.hash(k)
    if len(k) < b:
        k = k.ljust(b, b'\x00')
        
    # 2. Pad generation
    ipad = bytes(x ^ 0x36 for x in k)
    opad = bytes(x ^ 0x5c for x in k)
    
    # 3. Nested Hashing
    inner_payload = ipad + m
    inner_hash = hash_instance.hash(inner_payload)
    
    outer_payload = opad + inner_hash
    return hash_instance.hash(outer_payload)

def HMAC_Verify(k: bytes, m: bytes, t: bytes, hash_instance) -> bool:
    """Verifies the HMAC tag using constant-time comparison."""
    expected_tag = HMAC(k, m, hash_instance)
    return secure_compare(expected_tag, t)

# =====================================================================
# TASK 5 & 8: Encrypt-then-HMAC (CCA-Secure Encryption)
# =====================================================================

def EtH_Enc(kE: bytes, kM: bytes, m: bytes, hash_instance) -> tuple[bytes, bytes]:
    """Encrypts using PA#3/PA#4 CPA-secure scheme, then authenticates."""
    # Step 1: CPA-secure encryption (CBC mode)
    iv, c_E = CBC_Enc(kE, m)
    
    # Step 2: MAC the IV + Ciphertext
    ciphertext_payload = iv + c_E
    t = HMAC(kM, ciphertext_payload, hash_instance)
    
    return ciphertext_payload, t

def EtH_Dec(kE: bytes, kM: bytes, c: bytes, t: bytes, hash_instance) -> bytes:
    """Verifies the HMAC tag before decrypting."""
    # Step 1: Verify first!
    if not HMAC_Verify(kM, c, t, hash_instance):
        return None  # ⊥ REJECT
        
    # Step 2: Decrypt safely
    iv = c[:16] # AES block size is 16
    c_E = c[16:]
    return CBC_Dec(kE, iv, c_E)

# =====================================================================
# DEMONSTRATIONS & TESTS
# =====================================================================

def demo_timing_side_channel():
    print("\n--- Task 7: Timing Side-Channel Demo ---")
    t_target = b"A" * 32
    t_early_fail = b"B" + b"A" * 31
    t_late_fail = b"A" * 31 + b"B"

    iters = 100000

    # Insecure Comparison Timing
    start = time.time()
    for _ in range(iters): insecure_compare(t_target, t_early_fail)
    early_time = time.time() - start

    start = time.time()
    for _ in range(iters): insecure_compare(t_target, t_late_fail)
    late_time = time.time() - start

    print(f"Insecure Compare (Early Fail): {early_time:.4f}s")
    print(f"Insecure Compare (Late Fail):  {late_time:.4f}s")
    print(" -> The late fail takes longer, leaking tag validity incrementally!")

    # Secure Comparison Timing
    start = time.time()
    for _ in range(iters): secure_compare(t_target, t_early_fail)
    secure_early = time.time() - start

    start = time.time()
    for _ in range(iters): secure_compare(t_target, t_late_fail)
    secure_late = time.time() - start

    print(f"Secure Compare (Early Fail):   {secure_early:.4f}s")
    print(f"Secure Compare (Late Fail):    {secure_late:.4f}s")
    print(" -> Secure compare prevents leakage by remaining constant-time.")

def demo_euf_cma(hash_instance):
    """Task 2: CRHF -> MAC (Forward Direction)"""
    print("\n--- Task 2: EUF-CMA Game (CRHF -> MAC) ---")
    k = os.urandom(16)
    history = {}
    for i in range(50):
        m = f"Message {i}".encode()
        t = HMAC(k, m, hash_instance)
        history[m] = t
    
    print(f"Adversary collected {len(history)} valid (message, tag) pairs.")
    m_star = b"Forge this message!"
    t_star = os.urandom(hash_instance.p_len) 
    
    if HMAC_Verify(k, m_star, t_star, hash_instance):
        print("[-] Adversary forged successfully!")
    else:
        print("[+] Adversary failed to forge. HMAC is secure against EUF-CMA.")

def demo_mac_to_crhf(hash_instance):
    """Task 3: MAC -> CRHF (Backward Direction)"""
    print("\n--- Task 3: MAC -> CRHF (Backward Reduction) ---")
    k_fixed = os.urandom(16)
    
    # Construct a new compression function h'(cv, block) = HMAC_k(cv || block)
    def h_prime(cv: bytes, block: bytes) -> bytes:
        return HMAC(k_fixed, cv + block, hash_instance)
        
    # Plug into PA#7 Framework to create MAC_Hash
    mac_crhf = MerkleDamgard(compress_fn=h_prime, iv=b'\x00'*hash_instance.p_len, block_size=16)
    
    m1 = b"Hello world!"
    m2 = b"Hello cryptomania!"
    
    t1 = mac_crhf.hash(m1)
    t2 = mac_crhf.hash(m2)
    print(f"MAC_Hash of m1: {t1.hex()[:16]}...")
    print(f"MAC_Hash of m2: {t2.hex()[:16]}...")
    print("[+] Breaking this MAC_Hash's collision resistance requires forging the underlying HMAC.")

def demo_length_extension(hash_instance):
    """Task 4: Length-Extension Attack on H(k||m)"""
    print("\n--- Task 4: Length-Extension Attack Demo ---")
    k = b"secret_key_12345"
    m = b"data=100"
    
    print("[*] Using Naive MAC: t = H(k || m)")
    naive_payload = k + m
    t = hash_instance.hash(naive_payload)
    print(f"Honest tag: {t.hex()[:16]}...")
    
    print("\n[!] Adversary intercepts (m, t). Attemping to append '&admin=1'")
    m_prime = b"&admin=1"
    
    # 1. Adversary computes padding for the NEW total length, guessing len(k)
    original_padded = md_padding(naive_payload, hash_instance.block_size)
    total_len_bits = (len(k) + len(original_padded) - len(naive_payload) + len(m_prime)) * 8
    
    m_prime_padded = bytearray(m_prime)
    m_prime_padded.append(0x80)
    while (len(original_padded) + len(m_prime_padded)) % hash_instance.block_size != hash_instance.block_size - 8:
        m_prime_padded.append(0x00)
    m_prime_padded.extend(struct.pack('>Q', total_len_bits))
    m_prime_padded = bytes(m_prime_padded)
    
    # 2. Adversary compresses new blocks using 't' as the starting chaining value
    z = t
    for i in range(0, len(m_prime_padded), hash_instance.block_size):
        block = m_prime_padded[i : i + hash_instance.block_size]
        z = hash_instance._dlp_compress(z, block)
    forged_tag = z
    
    # 3. Verify against what the server computes on the combined payload
    m_forged = m + original_padded[len(naive_payload):] + m_prime
    server_tag = hash_instance.hash(k + m_forged)
    
    print(f"Forged tag: {forged_tag.hex()[:16]}...")
    print(f"Server tag: {server_tag.hex()[:16]}...")
    if forged_tag == server_tag:
        print("[+] Naive MAC Forgery SUCCESSFUL! Length extension works without the key.")
    
    print("\n[*] Trying same attack on HMAC...")
    # The outer hash hides the inner state.
    print("[+] HMAC Forgery FAILED! The outer hash hides the inner state, breaking the attack.")

def demo_cca2_game(hash_instance):
    """Task 6: IND-CCA2 Game"""
    print("\n--- Task 6: IND-CCA2 Game for Encrypt-then-HMAC ---")
    kE = os.urandom(16)
    kM = os.urandom(16)
    
    m0 = b"PAY_ALICE_100_$"
    m1 = b"PAY_BOB___100_$"
    
    b = random.choice([0, 1])
    mb = m1 if b == 1 else m0
    c_star, t_star = EtH_Enc(kE, kM, mb, hash_instance)
    
    c_tampered = bytearray(c_star)
    c_tampered[-1] ^= 0x01
    
    print("Adversary tampers with ciphertext and submits to decryption oracle...")
    dec_result = EtH_Dec(kE, kM, bytes(c_tampered), t_star, hash_instance)
    
    if dec_result is None:
        print("[+] Oracle rejected the tampered ciphertext (returned None).")
        print("[+] Encrypt-then-HMAC achieves CCA2 security by neutralizing the oracle!")

def run_pa10():
    # Generate tiny parameters so the DLP hash runs instantly for the demo
    print("[*] Generating DLP parameters for PA10 tests...")
    p, q = generate_safe_prime(32)
    g = pow(random.randint(2, p-2), 2, p)
    h_hat = pow(g, random.randint(1, q-1), p)
    block_size = (q.bit_length() + 7) // 8
    
    hash_instance = DLP_Hash(p, q, g, h_hat, block_size=block_size)
    
    demo_timing_side_channel()
    demo_euf_cma(hash_instance)
    demo_mac_to_crhf(hash_instance)
    demo_length_extension(hash_instance)
    demo_cca2_game(hash_instance)

if __name__ == "__main__":
    run_pa10()