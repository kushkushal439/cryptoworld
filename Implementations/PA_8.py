# Implementations/PA_8.py

import os
import random
import math

# Import the Merkle-Damgård framework from PA #7
from PA_7 import MerkleDamgard

# Import the rigorous Miller-Rabin primality test from PA #13
from PA_13 import is_prime

# =====================================================================
# 1. Number Theoretic Utilities (Linked to PA #13)
# =====================================================================

def generate_safe_prime(bits: int) -> tuple[int, int]:
    """
    Generates a safe prime p = 2q + 1, where q is also prime.
    Relies on the Miller-Rabin test implemented in PA #13.
    Returns (p, q).
    """
    while True:
        # Generate a prime q of size (bits - 1)
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1  # Ensure it has the correct bit length and is odd
        
        # Use PA #13's is_prime (Miller-Rabin)
        if is_prime(q):
            p = 2 * q + 1
            if is_prime(p):
                return p, q

def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean Algorithm for modular inverse."""
    m0, x0, x1 = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += m0
    return x1

# =====================================================================
# 2. DLP-Based Hash Implementation
# =====================================================================

class DLP_Hash:
    def __init__(self, p: int, q: int, g: int, h_hat: int, block_size: int = 32):
        self.p = p
        self.q = q
        self.g = g
        self.h_hat = h_hat
        self.block_size = block_size
        self.p_len = (p.bit_length() + 7) // 8
        
        # Instantiate the PA#7 Framework using the DLP compression logic
        self.iv = b'\x00' * self.p_len
        self.md_hasher = MerkleDamgard(
            compress_fn=self._dlp_compress, 
            iv=self.iv, 
            block_size=self.block_size
        )

    def _dlp_compress(self, chaining_val: bytes, block: bytes) -> bytes:
        """
        The core DLP compression function: h(x, y) = g^x * h_hat^y mod p
        x comes from the chaining value, y comes from the message block.
        """
        x = int.from_bytes(chaining_val, 'big') % self.q
        y = int.from_bytes(block, 'big') % self.q
        
        res = (pow(self.g, x, self.p) * pow(self.h_hat, y, self.p)) % self.p
        
        # Return as bytes matching the size of p to serve as the next chaining value
        return res.to_bytes(self.p_len, 'big')

    def hash(self, message: bytes, output_len: int = None) -> bytes:
        """
        Hashes an arbitrary length message.
        If output_len is specified, truncates the final digest (used in PA#9).
        """
        digest = self.md_hasher.hash(message)
        if output_len is not None:
            return digest[-output_len:]
        return digest

# =====================================================================
# 3. Collision Resistance Demo (The Birthday Attack)
# =====================================================================

def demo_collision_resistance():
    """
    Demonstrates that finding a collision in the DLP compression function
    is mathematically equivalent to solving the Discrete Logarithm Problem.
    Uses a tiny 16-bit safe prime.
    """
    print("\n--- DLP Collision Resistance Demo (Tiny Parameters) ---")
    
    # 1. Setup tiny group (q ~ 15 bits, p ~ 16 bits)
    print("[*] Generating tiny safe prime (~16 bits) using PA#13 logic...")
    p, q = generate_safe_prime(16)
    
    # Generator g (ensure it's in the subgroup of order q)
    g = pow(random.randint(2, p-2), 2, p)
    
    # Secret alpha, public h_hat
    alpha = random.randint(1, q - 1)
    h_hat = pow(g, alpha, p)
    
    print(f"    p: {p}, q: {q}")
    print(f"    g: {g}, h_hat: {h_hat} (Secret alpha: {alpha})")
    
    # 2. The Birthday Attack Brute Force
    print(f"[*] Brute-forcing a collision... (Expected tries: ~O(sqrt(q)) = ~{int(math.sqrt(q))})")
    seen = {}
    tries = 0
    collision_found = False
    
    while not collision_found:
        tries += 1
        x = random.randint(0, q - 1)
        y = random.randint(0, q - 1)
        
        # h(x,y) = g^x * h_hat^y mod p
        res = (pow(g, x, p) * pow(h_hat, y, p)) % p
        
        if res in seen:
            x_old, y_old = seen[res]
            if (x, y) != (x_old, y_old):
                print(f"[+] Collision Found after {tries} hashes!")
                print(f"    Pair 1: x={x_old}, y={y_old}")
                print(f"    Pair 2: x={x}, y={y}")
                print(f"    Shared Output: {res}")
                
                # 3. The Reduction Proof: Extracting Alpha
                delta_x = (x_old - x) % q
                delta_y = (y - y_old) % q
                
                if math.gcd(delta_y, q) == 1:
                    delta_y_inv = mod_inverse(delta_y, q)
                    recovered_alpha = (delta_x * delta_y_inv) % q
                    
                    print("\n[*] Mathematical Reduction Executing...")
                    print(f"    g^(x-x') = h_hat^(y'-y) mod p")
                    print(f"    Recovered alpha = (x-x') * (y'-y)^-1 mod q")
                    print(f"    Recovered alpha: {recovered_alpha}")
                    
                    assert recovered_alpha == alpha, "Reduction failed!"
                    print("\n[!] SUCCESS: Finding a collision solved the Discrete Logarithm! "
                          "Therefore, if DLP is hard, collisions are impossible to find.")
                    collision_found = True
        
        seen[res] = (x, y)

# =====================================================================
# 4. Integration Test
# =====================================================================

def integration_test():
    """Hashes 5 messages of different lengths to confirm distinct outputs."""
    print("\n--- Integration Test: Full DLP Hash ---")
    
    print("[*] Generating larger safe prime for integration test...")
    p, q = generate_safe_prime(64)
    g = pow(random.randint(2, p-2), 2, p)
    h_hat = pow(g, random.randint(1, q-1), p)
    
    block_size = (q.bit_length() + 7) // 8
    hasher = DLP_Hash(p, q, g, h_hat, block_size=block_size)
    
    messages = [
        b"",
        b"Hello",
        b"This is a block.",
        b"This message is intentionally much longer to force the Merkle-Damgard framework to run multiple rounds.",
        b"Different message, similar length to force the Merkle-Damgard framework to run multiple rounds."
    ]
    
    digests = set()
    for i, msg in enumerate(messages):
        digest = hasher.hash(msg)
        hex_digest = digest.hex()
        print(f"Msg {i+1} ({len(msg):>3} bytes) -> Digest: {hex_digest[:16]}...")
        digests.add(digest)
        
    assert len(digests) == 5, "Hash collision detected in integration test!"
    print("[+] All distinct messages produced distinct digests.")

if __name__ == "__main__":
    demo_collision_resistance()
    integration_test()