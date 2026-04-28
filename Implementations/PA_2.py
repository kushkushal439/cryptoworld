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

def ggm_prf_logic(prg_instance, key: bytes, query: str) -> bytes:
    """
    GGM Tree Construction.
    Takes an n-bit key (seed) and an n-bit query (binary string).
    """
    current_state = key
    
    # The PRG must double the state size at each tree node
    output_length = len(key) * 2

    for bit in query:
        # 1. Expand the current state using the PRG
        expanded = prg_instance.generate(seed=current_state, length=output_length)
        
        # 2. Split into G0 (Left) and G1 (Right)
        half_len = len(expanded) // 2
        G0 = expanded[:half_len]
        G1 = expanded[half_len:]
        
        # 3. Traverse down the tree based on the query bit
        if bit == '0':
            current_state = G0
        elif bit == '1':
            current_state = G1
        else:
            raise ValueError("GGM query must be a binary string (e.g., '1011')")
            
    # The final state at the leaf node is the PRF output
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



if __name__ == "__main__":
    demo_prf_distinguishing_game()