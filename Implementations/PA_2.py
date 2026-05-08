import os
import random
from collections import Counter

from CryptoPrimitives.PRF import PRF
from CryptoPrimitives.PRG import PRG

# Optional: Import AES for the Distinguishing Game demo
from CryptoPrimitives.AES import aes_prf


## Libraries used for the statistical tests
import math
import scipy.special as spc
import scipy.stats as stats

# =====================================================================
# 1. PA #2a: GGM PRF FROM PRG (Forward Direction)
# =====================================================================

from typing import Any

def ggm_prf_logic(prg_instance, key: bytes, query: Any) -> bytes:
    """
    GGM Tree Construction.
    Takes an n-bit key (seed) and an n-bit query.
    """
    # 1. Handle byte queries from the UI / AES pipeline
    if isinstance(query, bytes):
        query = "".join(format(b, '08b') for b in query)
    
    # print("lenght issss:::")
    # print(len(query))
        
    # SAFETY NET: GGM tree traversal is computationally expensive for DLP.
    # To prevent Flask from hanging during UI traces, we cap the traversal depth.
    # We use a custom deterministic 8-bit reduction (FNV-1a like) to avoid hashlib dependencies.
    if len(query) > 8:
        hash_val = 0x811c9dc5
        for char in query:
            hash_val ^= ord(char)
            hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF
        query = format(hash_val & 0xFF, '08b')

    current_state = key
    # We explicitly define the bytes we need
    req_bytes = len(key) * 2

    for bit in query:
        # Ask for bits first (for PA_1 DLP PRG compatibility)
        expanded = prg_instance.generate(seed=current_state, length=req_bytes * 8)
        
        # Truncate to the bytes we actually need
        if len(expanded) >= req_bytes:
            expanded = expanded[:req_bytes]
        else:
            # Fallback just in case the PRG treats length strictly as bytes
            # print("HUHHHH")
            expanded = prg_instance.generate(seed=current_state, length=req_bytes)
            expanded = expanded[:req_bytes]
            
        # Split into G0 (Left) and G1 (Right)
        half_len = len(expanded) // 2
        G0 = expanded[:half_len]
        G1 = expanded[half_len:]
        
        # Traverse down the tree
        if bit == '0':
            current_state = G0
        elif bit == '1':
            current_state = G1
        else:
            raise ValueError("GGM query must be a binary string (e.g., '1011')")
            
    return current_state


def convert_prg_to_prf(prg_instance: PRG) -> PRF:
    """
    Wraps the GGM logic inside a PRF container.
    Import this in God.py for the convert_prg_to_prf method.
    """
    return PRF(
        underlying_primitive=prg_instance,
        logic_func=ggm_prf_logic,
        block_size=None  # GGM block size depends dynamically on the input key size
    )


# =====================================================================
# 2. PA #2b: PRG FROM PRF (Backward Direction)
# =====================================================================

def prf_to_prg_logic(prf_instance, seed: bytes, length: int) -> bytes:
    """
    Constructs a length-doubling PRG from a PRF: G(s) = F_s(0^n) || F_s(1^n)
    """
    n_bytes = len(seed)
    
    # We dynamically format the query based on the PRF's required interface
    # AES expects raw bytes, whereas our GGM expects a binary string
    if getattr(prf_instance, 'block_size', None) is not None:
        query_0 = b'\x00' * prf_instance.block_size
        query_1 = b'\xff' * prf_instance.block_size 
    else:
        query_0 = '0' * (n_bytes * 8)
        query_1 = '1' * (n_bytes * 8)
        
    out_0 = prf_instance.evaluate(key=seed, query=query_0)
    out_1 = prf_instance.evaluate(key=seed, query=query_1)
    
    # Concatenate to double the length
    pseudorandom_stream = out_0 + out_1
    
    # Truncate to the requested length just in case
    return pseudorandom_stream[:length]


def convert_prf_to_prg(prf_instance: PRF) -> PRG:
    """
    Wraps the backward logic inside a PRG container.
    Import this in God.py for the convert_prf_to_prg method.
    """
    return PRG(
        logic_func=lambda seed, length: prf_to_prg_logic(prf_instance, seed, length)
    )


# =====================================================================
# 3. ATTACK / SECURITY DEMONSTRATIONS (NIST SP 800-22 Tests)
# =====================================================================

def bytes_to_bit_list(byte_data: list[bytes]) -> list[int]:
    """Converts a list of byte strings into a flat list of integers (0 or 1)."""
    bits = []
    for block in byte_data:
        for byte in block:
            bits.extend((byte >> i) & 1 for i in range(7, -1, -1))
    return bits

class NIST_Tests:
    """
    Implements the three required NIST SP 800-22 statistical tests.
    A p-value >= 0.01 indicates the sequence is pseudorandom.
    """
    
    @staticmethod
    def monobit_test(bits: list[int]) -> float:
        """Frequency (Monobit) Test."""
        n = len(bits)
        ones = sum(bits)
        zeros = n - ones
        s_obs = abs(ones - zeros) / math.sqrt(n)
        
        # Using scipy for the complementary error function
        return spc.erfc(s_obs / math.sqrt(2))

    @staticmethod
    def runs_test(bits: list[int]) -> float:
        """Runs Test."""
        n = len(bits)
        ones = sum(bits)
        pi = ones / n
        
        # Prerequisite check: is the frequency roughly 50/50?
        if abs(pi - 0.5) >= (2.0 / math.sqrt(n)):
            return 0.0 

        # Count the number of runs
        v_obs = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
                
        num = abs(v_obs - 2 * n * pi * (1 - pi))
        den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        
        return spc.erfc(num / den)

    @staticmethod
    def serial_test(bits: list[int]) -> tuple[float, float]:
        """
        Serial Test (m=2). 
        Returns two p-values (p_value1, p_value2). Both must be >= 0.01.
        """
        n = len(bits)
        bits_ext = bits + [bits[0]]

        # Frequencies for 2-bit (m) and 1-bit (m-1) patterns
        v2 = {(0, 0): 0, (0, 1): 0, (1, 0): 0, (1, 1): 0}
        v1 = {0: 0, 1: 0}

        for i in range(n):
            v2[(bits_ext[i], bits_ext[i+1])] += 1
            v1[bits_ext[i]] += 1

        psi_2 = (4 / n) * sum(v**2 for v in v2.values()) - n
        psi_1 = (2 / n) * sum(v**2 for v in v1.values()) - n
        psi_0 = 0 

        del1 = psi_2 - psi_1
        del2 = psi_2 - 2 * psi_1 + psi_0

        # Using scipy's chi-squared survival function (sf = 1 - cdf)
        p_value1 = stats.chi2.sf(del1, df=2)
        p_value2 = stats.chi2.sf(del2, df=1)
        
        return p_value1, p_value2

# =====================================================================
# 4. PA #2d: Distinguishing Game
# =====================================================================

def demo_prf_distinguishing_game():
    """
    Queries a PRF on q=100 random inputs and runs the NIST test suite 
    to empirically support PRF security.
    """
    print("\n--- Initiating PRF Distinguishing Game & NIST Tests ---")
    
    # Using the AES PRF for the demo (or swap with your GGM PRF)
    from CryptoPrimitives.AES import aes_prf 
    
    secret_key = os.urandom(16)
    queries = [os.urandom(16) for _ in range(100)]
    
    prf_outputs = [aes_prf.evaluate(secret_key, q) for q in queries]
    bits = bytes_to_bit_list(prf_outputs)
    
    print(f"Generated {len(bits)} bits for statistical testing...\n")
    print(f"{'Test Name':<20} | {'p-value':<10} | {'Result'}")
    print("-" * 50)
    
    p_mono = NIST_Tests.monobit_test(bits)
    print(f"{'Frequency (Monobit)':<20} | {p_mono:<10.4f} | {'PASS' if p_mono >= 0.01 else 'FAIL'}")
    
    p_runs = NIST_Tests.runs_test(bits)
    print(f"{'Runs':<20} | {p_runs:<10.4f} | {'PASS' if p_runs >= 0.01 else 'FAIL'}")
    
    p_serial1, p_serial2 = NIST_Tests.serial_test(bits)
    serial_pass = "PASS" if (p_serial1 >= 0.01 and p_serial2 >= 0.01) else "FAIL"
    print(f"{'Serial (P-val 1)':<20} | {p_serial1:<10.4f} | {serial_pass}")
    print(f"{'Serial (P-val 2)':<20} | {p_serial2:<10.4f} | {serial_pass}")


def split_bytes(data: bytes) -> tuple[bytes, bytes]:
    """Splits a byte string evenly in half."""
    if len(data) % 2 != 0:
        raise ValueError("Feistel network requires an even-length query.")
    half = len(data) // 2
    return data[:half], data[half:]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XORs two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def luby_rackoff_forward(prf_instance, key: bytes, query: bytes, rounds: int = 4) -> bytes:
    """
    Feistel Network (Forward).
    Converts a PRF into a PRP. 4 rounds yields a Strong PRP.
    """
    L, R = split_bytes(query)
    
    # We assume the master key is simply the concatenation of the independent round keys.
    # e.g., For a 4-round AES-based Feistel, the master key is 64 bytes (4 x 16).
    prf_key_size = len(key) // rounds

    for i in range(rounds):
        round_key = key[i * prf_key_size : (i + 1) * prf_key_size]
        
        # 1. Evaluate the PRF on the Right half: F(K_i, R_{i-1})
        F_out = prf_instance.evaluate(round_key, R)
        
        # Truncate F_out if the PRF output is longer than our half-block
        F_out = F_out[:len(L)]
        
        # 2. Feistel Cross: L_i = R_{i-1}, R_i = L_{i-1} XOR F_out
        new_L = R
        new_R = xor_bytes(L, F_out)
        
        L, R = new_L, new_R
        
    return L + R

def luby_rackoff_inverse(prf_instance, key: bytes, query: bytes, rounds: int = 4) -> bytes:
    """
    Feistel Network (Inverse).
    Traverses the rounds in reverse order to exactly undo the permutation.
    Note: The underlying PRF is STILL evaluated in the forward direction!
    """
    L, R = split_bytes(query)
    prf_key_size = len(key) // rounds

    # Traverse keys backwards: K_4, K_3, K_2, K_1
    for i in range(rounds - 1, -1, -1):
        round_key = key[i * prf_key_size : (i + 1) * prf_key_size]
        
        # Undo the Feistel Cross:
        # Since Forward did: new_L = R, new_R = L XOR F_out
        # To reverse: old_R = L, old_L = R XOR F_out
        prev_R = L
        
        # The magic of Feistel: we still just evaluate the PRF forward!
        F_out = prf_instance.evaluate(round_key, prev_R)
        F_out = F_out[:len(R)]
        
        prev_L = xor_bytes(R, F_out)
        
        L, R = prev_L, prev_R
        
    return L + R



if __name__ == "__main__":
    demo_prf_distinguishing_game()