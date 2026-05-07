# Implementations/PA_9.py
import os
import random
import math
import time
from Implementations.PA_8 import DLP_Hash, generate_safe_prime

def toy_hash(message: bytes, n: int = 16) -> bytes:
    """A deliberately weak hash function for fast demonstrations."""
    val = int.from_bytes(message, 'big')
    mask = (1 << n) - 1
    hashed_val = (val * 12345 + 67890) & mask
    return hashed_val.to_bytes(max(1, math.ceil(n/8)), 'big')

class ToyHash:
    def __init__(self, n: int):
        self.n = n

    def hash(self, message: bytes) -> bytes:
        return toy_hash(message, self.n)

def naive_birthday_attack(hash_fn, n: int, yield_steps=False):
    """
    Finds a collision for hash_fn with n-bit output using a dictionary.
    Supports a generator mode (yield_steps=True) for the live web API.
    """
    seen_hashes = {}
    num_evaluations = 0
    
    while True:
        num_evaluations += 1
        rand_input = random.getrandbits(128).to_bytes(16, 'big')
        
        full_hash = hash_fn(rand_input)
        truncated_hash = int.from_bytes(full_hash, 'big') & ((1 << n) - 1)
        
        if yield_steps:
            is_collision = truncated_hash in seen_hashes
            yield {
                "k": num_evaluations,
                "x": rand_input.hex(),
                "hx": truncated_hash,
                "status": "collision" if is_collision else "hashing",
                "collision_pair": {
                    "x1": seen_hashes[truncated_hash].hex() if is_collision else "", 
                    "x2": rand_input.hex()
                } if is_collision else None
            }

        if truncated_hash in seen_hashes:
            input1 = seen_hashes[truncated_hash]
            input2 = rand_input
            if input1 != input2:
                if not yield_steps:
                    return input1, input2, truncated_hash.to_bytes(math.ceil(n/8), 'big'), num_evaluations
                else:
                    break
        else:
            seen_hashes[truncated_hash] = rand_input

def floyd_cycle_finding_attack(hash_fn, n: int):
    """
    Finds a collision using Floyd's tortoise-and-hare algorithm in O(1) space.
    Correctly traces back to find the exact colliding pre-images.
    """
    def f(input_bytes: bytes) -> bytes:
        h = hash_fn(input_bytes)
        output_int = int.from_bytes(h, 'big') & ((1 << n) - 1)
        return output_int.to_bytes(max(1, math.ceil(n/8)), 'big')

    evals = 0
    while True:
        x0 = os.urandom(max(1, math.ceil(n/8)))
        t = f(x0)
        h = f(f(x0))
        evals += 3

        # Phase 1: Find a point in the cycle
        while t != h:
            t = f(t)
            h = f(f(h))
            evals += 3
            
        # Phase 2: Find the start of the cycle (the collision)
        t = x0
        prev_t, prev_h = None, None
        
        while t != h:
            prev_t, prev_h = t, h
            t = f(t)
            h = f(h)
            evals += 2

        if prev_t is not None and prev_t != prev_h:
            collision_hash = int.from_bytes(t, 'big')
            return prev_t, prev_h, collision_hash, evals

def demo_attack_toy_hash():
    print("\n--- Attacking Toy Hash Function ---")
    for n in [8, 12, 16]:
        print(f"\n[*] Testing with n = {n} bits...")
        toy_hasher = ToyHash(n)
        theoretical_evals = math.sqrt(math.pi / 2) * (2**(n/2))
        
        start_time = time.time()
        _, _, _, evals = naive_birthday_attack(toy_hasher.hash, n)
        duration = time.time() - start_time
        
        print(f"    Collision found after {evals} evaluations.")
        print(f"    Theoretical expectation: ~{int(theoretical_evals)} evaluations.")
        print(f"    Ratio (Actual / Theoretical): {evals / theoretical_evals:.2f}")
        print(f"    Time taken: {duration:.4f} seconds.")

def empirical_birthday_curve():
    """Run 100 trials for n in {8, 10, 12, 14, 16} bits to prove the theoretical curve."""
    print("\n--- Empirical Birthday Curve (100 trials) ---")
    for n in [8, 10, 12, 14, 16]:
        print(f"[*] Running 100 trials for n = {n} bits...")
        toy_hasher = ToyHash(n)
        results = []
        for _ in range(100):
            _, _, _, evals = naive_birthday_attack(toy_hasher.hash, n)
            results.append(evals)
        
        avg_k = sum(results) / len(results)
        expected_k = math.sqrt(math.pi / 2) * (2**(n/2))
        
        print(f"    Avg hashes to collision: {avg_k:.2f}")
        print(f"    Theoretical expected:    {expected_k:.2f}")

def demo_attack_dlp_hash():
    print("\n--- Attacking Truncated DLP Hash (from PA#8) ---")
    n = 16 
    print("[*] Setting up DLP Hash with 64-bit prime...")
    p, q = generate_safe_prime(64)
    g = pow(random.randint(2, p-2), 2, p)
    h_hat = pow(g, random.randint(1, q-1), p)
    block_size = (q.bit_length() + 7) // 8
    hasher = DLP_Hash(p, q, g, h_hat, block_size=block_size)
    
    print(f"[*] Running birthday attack on DLP hash truncated to n={n} bits...")
    theoretical_evals = math.sqrt(math.pi / 2) * (2**(n/2))
    
    start_time = time.time()
    input1, input2, collision, evals = naive_birthday_attack(hasher.hash, n)
    duration = time.time() - start_time
    
    print(f"[+] Collision found after {evals} evaluations!")
    print(f"    Theoretical expectation: ~{int(theoretical_evals)} evaluations.")
    print(f"    Time taken: {duration:.4f} seconds.")
    print(f"    Colliding Input 1: {input1.hex()}")
    print(f"    Colliding Input 2: {input2.hex()}")

def analyze_real_world_hashes():
    print("\n--- Birthday Attack Complexity for Real-World Hashes ---")
    hashes_per_sec = 10**9 
    
    n_md5 = 128
    evals_md5 = 2**(n_md5 / 2)
    time_md5_sec = evals_md5 / hashes_per_sec
    print(f"\n[*] MD5 (n=128):")
    print(f"    Attack requires ~2^{n_md5/2} = {evals_md5:.2e} evaluations.")
    print(f"    At {hashes_per_sec/1e9:.1f} billion hashes/sec, this would take {time_md5_sec / (3600 * 24 * 365.25):.2e} years.")
    
    n_sha1 = 160
    evals_sha1 = 2**(n_sha1 / 2)
    time_sha1_sec = evals_sha1 / hashes_per_sec
    print(f"\n[*] SHA-1 (n=160):")
    print(f"    Attack requires ~2^{n_sha1/2} = {evals_sha1:.2e} evaluations.")
    print(f"    At {hashes_per_sec/1e9:.1f} billion hashes/sec, this would take {time_sha1_sec / (3600 * 24 * 365.25):.2e} years.")

if __name__ == "__main__":
    demo_attack_toy_hash()
    empirical_birthday_curve()
    demo_attack_dlp_hash()
    analyze_real_world_hashes()