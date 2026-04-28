# Implementations/PA_19.py

import random

# Import your PA#18 OT implementation
from Implementations.PA_18 import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2

# =====================================================================
# Privacy Proof (Informal Argument)
# =====================================================================
"""
Privacy Proof for Secure AND via OT:
(a) Bob's Privacy: Alice acts as the OT sender. As proven in PA#18, the OT sender 
    receives computationally indistinguishable keys (pk_0, pk_1) and cannot determine 
    which key contains the trapdoor. Therefore, Alice learns nothing about Bob's bit 'b'.
    
(b) Alice's Privacy: Bob acts as the OT receiver. Bob only possesses the private key 
    for his choice bit 'b'. He cannot decrypt the ciphertext for the other message. 
    Therefore, Bob learns m_b. If b=0, he receives m_0=0, learning nothing about m_1 (a).
    If b=1, he receives m_1=a (which equals 1 AND a), meaning the protocol output requires 
    him to know it anyway. Alice's input 'a' is perfectly hidden when b=0.
"""

# =====================================================================
# 1. Secure Gates
# =====================================================================

def AND(a: int, b: int) -> int:
    """
    Secure AND Gate using Oblivious Transfer.
    Alice holds 'a', Bob holds 'b'.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("Inputs must be bits (0 or 1)")
        
    # Bob (Receiver) prepares to receive based on his bit 'b'
    # We use 256 bits for speed. Messages are tiny (1 byte).
    pk_0, pk_1, state = OT_Receiver_Step1(b=b, bits=256)
    
    # Alice (Sender) prepares her two messages: m0 = 0, m1 = a
    # Convert to 1-byte strings since OT expects bytes
    m_0 = (0).to_bytes(1, 'big')
    m_1 = a.to_bytes(1, 'big')
    
    # Alice encrypts and sends
    c_0, c_1 = OT_Sender_Step(pk_0, pk_1, m_0, m_1)
    
    # Bob decrypts the ciphertext corresponding to his bit 'b'
    recovered_bytes = OT_Receiver_Step2(state, c_0, c_1, b)
    
    # The recovered byte is the integer answer (a AND b)
    result = int.from_bytes(recovered_bytes, 'big')
    return result

def XOR(a: int, b: int) -> int:
    """
    Secure XOR using additive secret sharing over Z2 (as specified).
    Alice holds 'a', Bob holds 'b'.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("Inputs must be bits (0 or 1)")
        
    # Alice generates random bit r and sends to Bob
    r = random.choice([0, 1])
    
    # Alice computes her local share
    alice_share = a ^ r
    
    # Bob computes his local share
    bob_share = b ^ r
    
    # The final output is the XOR of both shares
    # (a ^ r) ^ (b ^ r) = a ^ b ^ r ^ r = a ^ b
    return alice_share ^ bob_share

def NOT(a: int) -> int:
    """Secure NOT gate (Local operation)."""
    if a not in (0, 1):
        raise ValueError("Input must be bit (0 or 1)")
    return a ^ 1

# =====================================================================
# 2. Tests
# =====================================================================

def test_truth_tables():
    print("\n--- Running Truth Table Tests (50 iterations per combination) ---")
    
    combinations = [(0, 0), (0, 1), (1, 0), (1, 1)]
    
    for a, b in combinations:
        expected_and = a & b
        expected_xor = a ^ b
        
        for _ in range(50):
            # Test AND
            res_and = AND(a, b)
            assert res_and == expected_and, f"AND Failed for {a}, {b}!"
            
            # Test XOR
            res_xor = XOR(a, b)
            assert res_xor == expected_xor, f"XOR Failed for {a}, {b}!"
            
        print(f"[+] Tested a={a}, b={b}   ->   AND={expected_and}, XOR={expected_xor}")
        
    print("\n[!] All 4 input combinations passed 50 runs successfully.")
    
def test_not():
    print("\n--- Running NOT Gate Test ---")
    assert NOT(0) == 1
    assert NOT(1) == 0
    print("[+] NOT gate test passed.")

if __name__ == "__main__":
    test_not()
    # Note: Running 200 OT evaluations (4 combos * 50) with 256-bit RSA 
    # will take a few seconds.
    test_truth_tables()