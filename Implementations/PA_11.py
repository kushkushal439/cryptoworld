# Implementations/PA_11.py

import random
import time

# Importing our core math utilities from PA #13 to enforce the no-library rule
from PA_13 import is_prime, square_and_multiply

# =====================================================================
# 1. GROUP PARAMETER GENERATION
# =====================================================================

def generate_dh_parameters(bits: int) -> tuple[int, int, int]:
    """
    Generates Diffie-Hellman parameters: a safe prime p = 2q + 1, 
    and a generator g of the prime-order subgroup of order q.
    """
    while True:
        # Generate a candidate prime q of size (bits - 1)
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1  # Ensure MSB and LSB are 1
        
        if is_prime(q):
            p = 2 * q + 1
            if is_prime(p):
                break  # Found our safe prime p

    # Find a generator g for the subgroup of order q
    # For a safe prime p, an element h has order q if h^2 != 1 mod p and h^q = 1 mod p.
    # Squaring a random element h (where h != 1 and h != p-1) guarantees it falls 
    # into the subgroup of quadratic residues, which has order q.
    while True:
        h = random.randint(2, p - 2)
        g = square_and_multiply(h, 2, p)
        if g != 1:
            return p, q, g


# =====================================================================
# 2. DIFFIE-HELLMAN KEY EXCHANGE PROTOCOL
# =====================================================================

def dh_alice_step1(p: int, q: int, g: int) -> tuple[int, int]:
    """Alice samples private 'a' and computes public 'A'."""
    a = random.randint(1, q - 1)
    A = square_and_multiply(g, a, p)
    return a, A

def dh_bob_step1(p: int, q: int, g: int) -> tuple[int, int]:
    """Bob samples private 'b' and computes public 'B'."""
    b = random.randint(1, q - 1)
    B = square_and_multiply(g, b, p)
    return b, B

def dh_alice_step2(a: int, B: int, p: int) -> int:
    """Alice computes the shared secret K = B^a mod p."""
    return square_and_multiply(B, a, p)

def dh_bob_step2(b: int, A: int, p: int) -> int:
    """Bob computes the shared secret K = A^b mod p."""
    return square_and_multiply(A, b, p) 


# =====================================================================
# 3. ATTACK DEMONSTRATIONS
# =====================================================================

def demo_mitm_attack(p: int, q: int, g: int):
    """
    Demonstrates an active Man-in-the-Middle (MITM) attack where Eve 
    establishes separate shared secrets with Alice and Bob.
    """
    print("\n--- Man-in-the-Middle (MITM) Attack Demo ---")
    
    # 1. Alice and Bob generate their honest values
    a, A = dh_alice_step1(p, q, g)
    b, B = dh_bob_step1(p, q, g)
    
    # 2. Eve intercepts A and B, and substitutes her own values
    e = random.randint(1, q - 1)
    A_prime = square_and_multiply(g, e, p)  # Sent to Bob masquerading as A
    B_prime = square_and_multiply(g, e, p)  # Sent to Alice masquerading as B
    
    print("[!] Eve intercepted A and B, sending malicious A_prime and B_prime.")

    # 3. Alice and Bob compute what they THINK is their shared secret
    K_Alice = dh_alice_step2(a, B_prime, p)
    K_Bob = dh_bob_step2(b, A_prime, p)
    
    # 4. Eve computes the separate shared secrets
    K_Eve_Alice = square_and_multiply(A, e, p)
    K_Eve_Bob = square_and_multiply(B, e, p)
    
    print(f"Alice's derived secret: {K_Alice}")
    print(f"Eve's secret w/ Alice:  {K_Eve_Alice}")
    print(f"Bob's derived secret:   {K_Bob}")
    print(f"Eve's secret w/ Bob:    {K_Eve_Bob}")
    
    assert K_Alice == K_Eve_Alice, "Eve failed to match Alice's key!"
    assert K_Bob == K_Eve_Bob, "Eve failed to match Bob's key!"
    assert K_Alice != K_Bob, "Keys shouldn't match between Alice and Bob under MITM!"
    print("[+] MITM Attack Successful: Eve controls the channel.")


def demo_cdh_hardness():
    """
    Demonstrates that computing g^ab given g^a and g^b requires solving DLP.
    Uses small parameters to make the brute-force attack feasible.
    """
    print("\n--- CDH Hardness Demo (Small Parameters) ---")
    
    # Generate tiny parameters (q ~ 20 bits -> p ~ 21 bits)
    print("[*] Generating 20-bit group parameters...")
    p, q, g = generate_dh_parameters(20)
    print(f"    p: {p}, q: {q}, g: {g}")
    
    a, A = dh_alice_step1(p, q, g)
    b, B = dh_bob_step1(p, q, g)
    
    print(f"[*] Target A = {A}, B = {B}")
    print(f"[*] Starting brute force to solve DLP for 'a' (Expected: O(q) worst-case)...")
    
    start_time = time.time()
    recovered_a = None
    
    # Brute force search for 'a' by calculating g^x mod p sequentially
    current = 1
    for x in range(q):
        if current == A:
            recovered_a = x
            break
        current = (current * g) % p
        
    duration = time.time() - start_time
    
    if recovered_a is not None:
        print(f"[+] Recovered a={recovered_a} in {duration:.4f} seconds.")
        # Eve computes the shared secret using recovered 'a'
        K_Eve = square_and_multiply(B, recovered_a, p)
        K_Real = dh_alice_step2(a, B, p)
        
        print(f"    Eve's derived K: {K_Eve}")
        print(f"    Real Shared K:   {K_Real}")
        assert K_Eve == K_Real
        print("[+] CDH broken via DLP! (This is why we need large parameters).")
    else:
        print("[-] Failed to brute force.")


# =====================================================================
# 4. BASIC TESTS
# =====================================================================

def test_honest_protocol():
    """Basic sanity check ensuring Alice and Bob compute the same key."""
    print("\n--- Honest Diffie-Hellman Protocol Check ---")
    print("[*] Generating 256-bit parameters...")
    p, q, g = generate_dh_parameters(256)
    
    print("[*] Simulating Key Exchange...")
    a, A = dh_alice_step1(p, q, g)
    b, B = dh_bob_step1(p, q, g)
    
    K_A = dh_alice_step2(a, B, p)
    K_B = dh_bob_step2(b, A, p)
    
    assert K_A == K_B, "Honest protocol failed! Shared secrets do not match."
    print(f"[+] Protocol successful! Shared Secret: {hex(K_A)[:20]}...")


if __name__ == "__main__":
    # Note: If your square_and_multiply from PA_13 is strictly pure Python, 
    # generating 256-bit parameters might take a few seconds. 
    test_honest_protocol()
    
    # Using 64-bit parameters for MITM to keep execution snappy
    p_small, q_small, g_small = generate_dh_parameters(64)
    demo_mitm_attack(p_small, q_small, g_small)
    
    demo_cdh_hardness()