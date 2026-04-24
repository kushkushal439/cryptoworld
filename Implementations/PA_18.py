# Implementations/PA_18.py

import os
import random
import time

# Import your PA#12 RSA implementation
from Implementations.PA_12 import rsa_keygen, pkcs15_enc, pkcs15_dec

# =====================================================================
# 1. 1-out-of-2 Oblivious Transfer API
# =====================================================================

def OT_Receiver_Step1(b: int, bits: int = 512):
    """
    Receiver Step 1:
    Generates two public keys. Keeps the secret key for index 'b'.
    Creates a 'trapdoorless' key for index '1-b' by generating and discarding the secret.
    """
    if b not in [0, 1]:
        raise ValueError("Choice bit b must be 0 or 1.")
        
    # Generate two valid RSA keys
    pk_0, sk_0 = rsa_keygen(bits)
    pk_1, sk_1 = rsa_keygen(bits)
    
    if b == 0:
        state = sk_0     # Keep sk_0
        # sk_1 is destroyed/never saved
    else:
        state = sk_1     # Keep sk_1
        # sk_0 is destroyed/never saved
        
    return pk_0, pk_1, state

def OT_Sender_Step(pk_0: tuple, pk_1: tuple, m_0: bytes, m_1: bytes) -> tuple:
    """
    Sender Step 1:
    Encrypts m_0 under pk_0 and m_1 under pk_1.
    """
    # Use PKCS#1 v1.5 from PA#12 to be CPA-secure
    c_0 = pkcs15_enc(pk_0, m_0)
    c_1 = pkcs15_enc(pk_1, m_1)
    
    return c_0, c_1

def OT_Receiver_Step2(state: tuple, c_0: bytes, c_1: bytes, b: int) -> bytes:
    """
    Receiver Step 2:
    Decrypts the chosen ciphertext using the saved state (secret key).
    """
    if b == 0:
        return pkcs15_dec(state, c_0)
    else:
        return pkcs15_dec(state, c_1)


# =====================================================================
# 2. Demonstrations & Proofs
# =====================================================================

def demo_receiver_privacy():
    """
    Demonstrates that the sender cannot guess 'b'.
    Both pk_0 and pk_1 are valid RSA public keys (N, e). They are
    computationally indistinguishable.
    """
    print("\n--- Receiver Privacy Demo ---")
    print("[*] Receiver executing Step 1 for b=1...")
    pk_0, pk_1, _ = OT_Receiver_Step1(b=1, bits=256)
    
    print(f"    pk_0 given to Sender: N={pk_0[0]}, e={pk_0[1]}")
    print(f"    pk_1 given to Sender: N={pk_1[0]}, e={pk_1[1]}")
    print("[+] Both keys are valid RSA moduli generated from the same distribution.")
    print("    Without factoring N_0 and N_1, the Sender has zero information about which")
    print("    key the Receiver kept the trapdoor for.")

def demo_sender_privacy():
    """
    Demonstrates that the receiver cannot decrypt the message they didn't choose.
    """
    print("\n--- Sender Privacy Demo ---")
    m0, m1 = b"Secret Zero", b"Secret One"
    b = 0

    print(f"[*] Receiver chooses b={b}.")
    pk_0, pk_1, state = OT_Receiver_Step1(b, bits=256)
    c_0, c_1 = OT_Sender_Step(pk_0, pk_1, m0, m1)
    
    print("[*] Sender returns C_0 and C_1.")
    
    # Receiver successfully decrypts C_0
    recovered_m0 = OT_Receiver_Step2(state, c_0, c_1, b=0)
    print(f"[+] Receiver successfully decrypted C_b: {recovered_m0}")
    
    # Receiver attempts to decrypt C_1
    print("[*] Receiver attempting to cheat and decrypt C_1 without sk_1...")
    try:
        # State holds sk_0, applying it to c_1 will fail padding validation
        cheating_result = pkcs15_dec(state, c_1)
        if cheating_result is None:
            print("[+] Attack thwarted: PKCS#1 v1.5 padding validation failed.")
            print("    Decryption yielded ⊥. Receiver learns nothing about m_1.")
    except Exception as e:
         print(f"[+] Attack thwarted: Math failure ({e})")
         
    print("    To decrypt C_1, the Receiver would need to factor pk_1's N to find d_1.")

def test_correctness():
    """
    Runs 100 trials of random bits and messages to verify OT Correctness.
    """
    print("\n--- Correctness Test (100 Trials) ---")
    success_count = 0
    trials = 100
    
    start_time = time.time()
    
    for i in range(trials):
        b = random.choice([0, 1])
        m0 = os.urandom(4)  # Random 8 byte message
        m1 = os.urandom(4)
        
        # We use small bit sizes (128) just to make 100 trials run quickly
        pk_0, pk_1, state = OT_Receiver_Step1(b, bits=128)
        c_0, c_1 = OT_Sender_Step(pk_0, pk_1, m0, m1)
        recovered = OT_Receiver_Step2(state, c_0, c_1, b)
        
        expected = m0 if b == 0 else m1
        if recovered == expected:
            success_count += 1
            
    duration = time.time() - start_time
    print(f"[+] Results: {success_count}/{trials} OT exchanges successful.")
    print(f"    Completed in {duration:.2f} seconds.")
    assert success_count == trials, "Correctness test failed!"

if __name__ == "__main__":
    demo_receiver_privacy()
    demo_sender_privacy()
    test_correctness()