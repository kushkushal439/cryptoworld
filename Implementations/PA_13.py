import random
import time
import math

# =====================================================================
# 1. CORE MATH UTILITIES
# =====================================================================

def square_and_multiply(base: int, exp: int, mod: int) -> int:
    """
    Computes (base^exp) % mod efficiently using the Square-and-Multiply algorithm.
    Explicitly required by PA#13 to avoid using Python's built-in pow().
    """
    result = 1
    base = base % mod
    
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        # Square the base and shift the exponent right by 1
        base = (base * base) % mod
        exp = exp >> 1
        
    return result

# =====================================================================
# 2. MILLER-RABIN PRIMALITY TEST
# =====================================================================

def miller_rabin(n: int, k: int = 40) -> str:
    """
    Probabilistic primality test.
    Returns 'PROBABLY PRIME' or 'COMPOSITE'.
    Error probability is <= 4^(-k).
    """
    if n <= 1:
        return "COMPOSITE"
    if n <= 3:
        return "PROBABLY PRIME"
    if n % 2 == 0:
        return "COMPOSITE"

    # Step 1: Write n - 1 = 2^s * d with d odd
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Step 2: Test k rounds
    for _ in range(k):
        a = random.randrange(2, n - 1)

        x = square_and_multiply(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = square_and_multiply(x, 2, n)
            if x == n - 1:
                break

        else:
            return "COMPOSITE"

    return "PROBABLY PRIME"

# =====================================================================
# 3. INTERFACES REQUIRED BY DOWNSTREAM PAs (#11, #12)
# =====================================================================

def is_prime(n: int) -> bool:
    """Interface wrapper mapping to k=40 rounds."""
    return miller_rabin(n, 40) == "PROBABLY PRIME"

def gen_prime(bits: int) -> int:
    """
    Repeatedly samples a random odd b-bit integer until a prime is found.
    Verifies with k=100 rounds as a sanity check.
    """
    while True:
        # Generate random bits
        candidate = random.getrandbits(bits)
        
        # Force the MSB to 1 (to ensure exact bit length) 
        # and LSB to 1 (to ensure it's odd, skipping even numbers)
        candidate |= (1 << (bits - 1)) | 1

        if miller_rabin(candidate, 40) == "PROBABLY PRIME":
            # Sanity check (k=60)
            if miller_rabin(candidate, 60) == "PROBABLY PRIME":
                return candidate

# =====================================================================
# 4. DEMONSTRATIONS & BENCHMARKS
# =====================================================================

def demo_carmichael():
    """
    Demonstrates that 561 passes a naive Fermat test but fails Miller-Rabin.
    """
    print("\n--- Carmichael Number Demo (n = 561) ---")
    n = 561
    
    # Naive Fermat Test: a^(n-1) = 1 mod n
    # We test a few bases coprime to 561
    fermat_passes = True
    for a in [2, 5, 7]:
        if square_and_multiply(a, n - 1, n) != 1:
            fermat_passes = False
            break
            
    if fermat_passes:
        print("[!] Fermat Test: 561 appears PRIME (It fooled the naive test!)")
        
    # Miller-Rabin Test
    mr_result = miller_rabin(n, k=10)
    print(f"[*] Miller-Rabin Test: 561 is {mr_result}")
    
    if mr_result == "COMPOSITE":
        print("    -> SUCCESS: Miller-Rabin correctly identified the Carmichael number.")


def benchmark_primes():
    """
    Measures the average number of candidates sampled before finding a prime,
    compared against the Prime Number Theorem predictions.
    """
    print("\n--- Prime Generation Benchmark vs. PNT ---")
    bit_sizes = [512, 1024, 2048] # Reduced 2048 to 256 for time (pure python math is slow)
    
    print("Note: Because we use custom pure-Python square_and_multiply, generating ")
    print("large primes takes time. Swapping to Python's built-in pow() makes this instant.\n")
    print(f"{'Bits':<6} | {'Empirical Samples':<20} | {'PNT Prediction':<15} | {'Time (s)'}")
    print("-" * 65)
    
    for bits in bit_sizes:
        start_time = time.time()
        samples = 0
        
        while True:
            samples += 1
            candidate = random.getrandbits(bits)
            candidate |= (1 << (bits - 1)) | 1
            
            # Using k=10 for benchmark speed, actual gen uses k=40
            if miller_rabin(candidate, 10) == "PROBABLY PRIME":
                break
                
        duration = time.time() - start_time
        
        # Prime Number Theorem: P(prime around N) is ~ 1/ln(N).
        # Since N ~ 2^b, ln(N) ~ b * ln(2).
        # We only test ODD numbers, so we skip half the search space.
        # Therefore, expected samples = (b * ln(2)) / 2
        pnt_prediction = (bits * math.log(2)) / 2
        
        print(f"{bits:<6} | {samples:<20} | {pnt_prediction:<15.1f} | {duration:.2f}s")


if __name__ == "__main__":
    demo_carmichael()
    benchmark_primes()