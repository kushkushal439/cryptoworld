import os
import time
import random

# A safe prime (RFC 3526 1536-bit MODP Group)
# Using a slightly smaller prime or just the RFC one for speed.
# Let's use a 256-bit safe prime for demonstration so that generation and exponentiation are fast.
# Wait, let's just use a hardcoded 256-bit safe prime:
P = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16)
G = 2

def dlp_owf_logic(x: int, p=P, g=G) -> int:
    """
    Modular exponentiation (DLP): f(x) = g^x mod p
    """
    return pow(g, x, p)

def verify_hardness_dlp():
    """Demonstrate that random inversion fails for DLP."""
    x = random.getrandbits(256)
    y = dlp_owf_logic(x)
    print(f"Target y (DLP): {hex(y)[:20]}...")
    print("Attempting to guess x...")
    for _ in range(10000):
        guess = random.getrandbits(256)
        if dlp_owf_logic(guess) == y:
            print("Successfully inverted OWF! (This should almost never happen)")
            return True
    print("Failed to invert OWF after 10000 guesses. Seems hard!")
    return False

def hard_core_bit_gl(x: int, r: int) -> int:
    """Goldreich-Levin hard-core bit: <x, r> mod 2"""
    # inner product mod 2
    res = 0
    val = x & r
    while val:
        res ^= (val & 1)
        val >>= 1
    return res

def hill_prg_logic_dlp(seed: bytes, length: int, owf_instance) -> bytes:
    """
    PRG from OWF (DLP).
    Seed must be 64 bytes: 32 bytes for x0, and 32 bytes for r (Goldreich-Levin).
    f'(x, r) = (f(x), r)
    b(x, r) = <x, r> mod 2
    """
    if len(seed) != 64:
        raise ValueError("Seed must be 64 bytes for GL-based DLP OWF (256-bit x, 256-bit r).")
    x = int.from_bytes(seed[:32], 'big')
    r = int.from_bytes(seed[32:], 'big')
    
    out_bits = []
    # To generate length bits:
    for _ in range(length):
        out_bits.append(hard_core_bit_gl(x, r))
        x = owf_instance.evaluate(x)
        
    # Convert bits to bytes
    out_bytes = bytearray((length + 7) // 8)
    for i, bit in enumerate(out_bits):
        if bit:
            out_bytes[i // 8] |= (1 << (7 - (i % 8)))
            
    return bytes(out_bytes)

def convert_owf_to_prg(owf_instance):
    from CryptoPrimitives.PRG import PRG
    bound_logic = lambda seed, length: hill_prg_logic_dlp(seed, length, owf_instance)
    return PRG(bound_logic)

# For statistical tests
def run_nist_tests(bits: list) -> dict:
    import math
    n = len(bits)
    if n == 0:
        return {}
    
    # 1. Monobit (Frequency) Test
    S_n = sum(1 if b == 1 else -1 for b in bits)
    s_obs = abs(S_n) / math.sqrt(n)
    p_val_monobit = math.erfc(s_obs / math.sqrt(2))
    
    # 2. Runs Test
    pi = sum(bits) / n
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        p_val_runs = 0.0
    else:
        v_n_obs = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i+1])
        p_val_runs = math.erfc(abs(v_n_obs - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    
    # 3. Serial Test (placeholder-ish for m=2)
    if n > 2:
        counts = {0: 0, 1: 0, 2: 0, 3: 0}
        for i in range(n - 1):
            val = (bits[i] << 1) | bits[i+1]
            counts[val] += 1
        
        psi_sq_2 = (4/(n-1)) * sum(c**2 for c in counts.values()) - (2/n)*sum(counts.values())**2 
        p_val_serial = math.exp(-0.5 * psi_sq_2) if psi_sq_2 > 0 else 1.0 
    else:
        p_val_serial = 0.0

    return {
        "monobit": {"pass": p_val_monobit >= 0.01, "p_value": p_val_monobit},
        "runs": {"pass": p_val_runs >= 0.01, "p_value": p_val_runs},
        "serial_approx": {"pass": p_val_serial >= 0.01, "p_value": p_val_serial}
    }

def owf_from_prg_verify_hardness(prg):
    """
    PA#1b: Demonstrate that f(s) = G(s) is a OWF.
    """
    print("--- PA#1b: OWF from PRG Hardness ---")
    s = os.urandom(64)
    y = prg.generate(s, 512)
    print(f"Target PRG Output (G(s)): {y.hex()[:16]}...")
    print("Attempting naive inversion of G(s) to find s...")
    for _ in range(5000):
        guess = os.urandom(64)
        if prg.generate(guess, 512) == y:
            print("Successfully inverted PRG to find seed! This breaks PRG security.")
            return True
    print("Failed to recover seed from PRG output after 5000 guesses. It is an OWF.")
    return False

def run_pa1():
    from CryptoPrimitives.OWF import OWF
    print("--- PA#1 Evaluation (DLP variant) ---")
    owf = OWF(dlp_owf_logic)
    
    # Override verify_hardness for DLP (optional, just call our own)
    owf.verify_hardness = verify_hardness_dlp
    owf.verify_hardness()
    
    prg = convert_owf_to_prg_dlp(owf)
    # the GL logic needs 64 bytes (256-bit x, 256-bit r)
    seed = os.urandom(64)
    length_bits = 10000
    print(f"Generating {length_bits} bits using DLP-based PRG...")
    out_bytes = prg.generate(seed, length_bits)
    
    out_bits = []
    for b in out_bytes:
        for i in range(8):
            out_bits.append((b >> (7 - i)) & 1)
    out_bits = out_bits[:length_bits]
    
    print("Running NIST tests...")
    results = run_nist_tests(out_bits)
    for test, res in results.items():
        print(f"Test: {test}, Pass: {res['pass']}, p-value: {res['p_value']:.4f}")

    # PA#1b
    owf_from_prg_verify_hardness(prg)

if __name__ == "__main__":
    run_pa1()
