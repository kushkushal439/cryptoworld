import os
import random

# =====================================================================
# IMPORTS FROM PREVIOUS ASSIGNMENTS
# =====================================================================
from Implementations.PA_16 import elgamal_keygen, Enc as ElGamal_Enc, Dec as ElGamal_Dec, malleability_attack
from Implementations.PA_15 import Sign as RSA_Sign, Verify as RSA_Verify
from Implementations.PA_12 import rsa_keygen

# =====================================================================
# 1. HELPER: SERIALIZATION
# =====================================================================
def serialize_ciphertext(C_E: tuple) -> bytes:
    """
    Converts the ElGamal ciphertext tuple (c1, c2) into a deterministic 
    byte string so it can be hashed and signed by PA#15.
    """
    c1, c2 = C_E
    return f"{c1}||{c2}".encode('utf-8')


# =====================================================================
# 2. CORE CCA-SECURE PKC LOGIC (Encrypt-then-Sign)
# =====================================================================

def CCA_PKC_Enc(pk_enc: tuple, sk_sign: tuple, m: int) -> tuple[tuple, int]:
    """
    Encrypt-then-Sign Construction.
    1. Encrypts message using ElGamal (PA#16).
    2. Signs the resulting ciphertext using RSA (PA#15).
    """
    # 1. Encrypt: CE <- ElGamal_pk(m)
    C_E = ElGamal_Enc(pk_enc, m)
    
    # 2. Sign: \sigma
    C_E_bytes = serialize_ciphertext(C_E)
    sigma = RSA_Sign(sk_sign, C_E_bytes)

    return C_E, sigma


def CCA_PKC_Dec(sk_enc: int, pk_enc: tuple, vk_sign: tuple, C_E: tuple, sigma: int):
    """
    Verify-then-Decrypt Construction.
    Must verify the signature BEFORE attempting decryption.
    """
    C_E_bytes = serialize_ciphertext(C_E)
    
    # 1. Verify Vrfy_vk(CE, \sigma) == 1
    if not RSA_Verify(vk_sign, C_E_bytes, sigma):
        return None 
        
    # 2. Output ElGamal.Dec_sk(CE)
    # Note: PA#16 Dec requires pk_enc to extract p
    c1, c2 = C_E
    return ElGamal_Dec(sk_enc, pk_enc, c1, c2)


# =====================================================================
# 3. IND-CCA2 GAME FOR PKC
# =====================================================================

class CCA2_PKC_Challenger:
    def __init__(self, group_size="large"):
        # 1. Generate ElGamal Keys (Encryption)
        self.sk_enc, self.pk_enc = elgamal_keygen(group_size)
        
        # 2. Generate RSA Keys (Signing)
        # Using 512 or 1024 bits depending on your PA12 speed
        self.vk_sign, self.sk_sign = rsa_keygen(512) 
        
        self.challenge_ciphertext = None
        self.secret_bit = random.choice([0, 1])

    def decryption_oracle(self, C_E: tuple, sigma: int):
        """
        Adversary can query decryption of any ciphertext EXCEPT the challenge.
        """
        if self.challenge_ciphertext and (C_E, sigma) == self.challenge_ciphertext:
            return "REJECT: Cannot query the challenge ciphertext!"
            
        return CCA_PKC_Dec(self.sk_enc, self.pk_enc, self.vk_sign, C_E, sigma)

    def get_challenge(self, m0: int, m1: int):
        """Adversary submits two messages, gets one back signcrypted."""
        mb = m1 if self.secret_bit == 1 else m0
        
        # Encrypt and lock the state
        C_E, sigma = CCA_PKC_Enc(self.pk_enc, self.sk_sign, mb)
        self.challenge_ciphertext = (C_E, sigma)
        
        return self.challenge_ciphertext

    def verify_guess(self, guess: int):
        return guess == self.secret_bit


# =====================================================================
# 4. ATTACK DEMONSTRATIONS: MALLEABILITY CONTRAST
# =====================================================================

def demo_malleability_contrast():
    """
    Demonstrates that plain ElGamal is malleable, but our new 
    Encrypt-then-Sign CCA scheme safely detects and rejects the tampering.
    """
    print("\n--- PA #17: Malleability Contrast (CPA vs CCA) ---")
    
    # Setup Keys
    sk_enc, pk_enc = elgamal_keygen("large")
    vk_sign, sk_sign = rsa_keygen(512)
    p = pk_enc[0]
    
    m = 1000  # Original plaintext
    multiplier = 5 # Adversary wants to change 1000 to 5000
    print(f"Original Plaintext (m): {m}")
    print(f"Adversary Target (5 * m): {m * multiplier}")
    
    # -------------------------------------------------------------
    # ATTACK 1: Plain ElGamal (PA #16)
    # -------------------------------------------------------------
    print("\n[1] Attacking Plain ElGamal (PA #16)...")
    c1, c2 = ElGamal_Enc(pk_enc, m)
    
    # Adversary intercepts and tampers without knowing 'm' or 'sk'
    tampered_c1, tampered_c2 = malleability_attack(pk_enc, c1, c2, multiplier)
    
    # Receiver unknowingly decrypts tampered ciphertext
    recovered_m_cpa = ElGamal_Dec(sk_enc, pk_enc, tampered_c1, tampered_c2)
    print(f"    -> Plain ElGamal Decrypted: {recovered_m_cpa}")
    if recovered_m_cpa == (m * multiplier) % p:
        print("    -> [!] SILENT FAILURE: Adversary successfully altered the message!")
        
    # -------------------------------------------------------------
    # ATTACK 2: CCA-Secure PKC (PA #17)
    # -------------------------------------------------------------
    print("\n[2] Attacking CCA-Secure PKC (PA #17)...")
    C_E_cca, sigma_cca = CCA_PKC_Enc(pk_enc, sk_sign, m)
    c1_cca, c2_cca = C_E_cca
    
    # Adversary intercepts and tries the exact same tampering
    tampered_c1_cca, tampered_c2_cca = malleability_attack(pk_enc, c1_cca, c2_cca, multiplier)
    tampered_C_E_cca = (tampered_c1_cca, tampered_c2_cca)
    
    # Receiver decrypts using the strict Verify-then-Decrypt protocol
    recovered_m_cca = CCA_PKC_Dec(sk_enc, pk_enc, vk_sign, tampered_C_E_cca, sigma_cca)
    
    if recovered_m_cca is None:
        print("    -> CCA-Secure Decrypted: None (⊥)")
        print("    -> [!] BLOCKED BY SIGNATURE: Tampering detected and safely rejected.")
    else:
        print(f"    -> CCA-Secure Failed to reject! Result: {recovered_m_cca}")

if __name__ == "__main__":
    demo_malleability_contrast()