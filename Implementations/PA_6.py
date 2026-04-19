import os
import random

from implementations.PA3 import cpa_enc_logic, cpa_dec_logic
from implementations.PA5 import prf_mac_logic, mac_vrfy_logic

from implementations.PA_5 import CPA_Oracle

# =====================================================================
# 1. CORE CCA-SECURE LOGIC (Encrypt-then-MAC)
# =====================================================================

def cca_enc_logic(k_E: bytes, k_M: bytes, m: bytes):
    """
    Encrypt-then-MAC construction.
    Keys k_E and k_M must be independent.
    """
    # 1. Encrypt with CPA scheme (from PA3)
    r, c_E = cpa_enc_logic(k_E, m)
    
    # 2. MAC the ciphertext tuple
    ciphertext_payload = r + c_E 
    t = prf_mac_logic(k_M, ciphertext_payload)    

    return r, c_E, t


def cca_dec_logic(k_E: bytes, k_M: bytes, r: bytes, c_E: bytes, t: bytes):
    """
    Decryption with strict Vrfy check to prevent Chosen-Ciphertext Attacks.
    """
    ciphertext_payload = r + c_E
    
    # 1. Verify integrity FIRST! 
    if not mac_vrfy_logic(k_M, ciphertext_payload, t):
        return None 
        
    # 2. Only if valid, proceed to decrypt
    return cpa_dec_logic(k_E, r, c_E)

# =====================================================================
# 2. IND-CCA2 CHALLENGER GAME STATE
# =====================================================================

class CCA_Challenger:
    def __init__(self, same_key=False):
        """
        Initializes the game. 
        If same_key=True, it intentionally introduces the PA#6 Key Separation vulnerability.
        """
        self.k_E = os.urandom(16)
        self.k_M = self.k_E if same_key else os.urandom(16)

        self.challenge_ciphertext = None
        self.secret_bit = random.choice([0, 1])

    def encrypt_oracle(self, m: bytes):
        """Allows adversary to get encryptions of arbitrary messages."""
        return cca_enc_logic(self.k_E, self.k_M, m)

    def mac_oracle(self, payload: bytes):
        """
        Adversary has access to a MAC oracle in a standard game.
        This is used to demonstrate the same-key exploit.
        """
        return prf_mac_logic(self.k_M, payload)

    def decrypt_oracle(self, r: bytes, c_E: bytes, t: bytes):
        """
        Allows adversary to decrypt anything EXCEPT the challenge ciphertext.
        """
        query_tuple = (r, c_E, t)

        if self.challenge_ciphertext and query_tuple == self.challenge_ciphertext:
            return "REJECT: Cannot query the challenge ciphertext!"

        return cca_dec_logic(self.k_E, self.k_M, r, c_E, t)

    def get_challenge(self, m0: bytes, m1: bytes):
        """Adversary submits two messages, gets one back encrypted."""
        if len(m0) != len(m1):
            raise ValueError("Messages must be the same length")
            
        mb = m1 if self.secret_bit == 1 else m0
        
        # Encrypt and lock the state
        r, c_E, t = cca_enc_logic(self.k_E, self.k_M, mb)
        self.challenge_ciphertext = (r, c_E, t)
        return self.challenge_ciphertext

    def verify_guess(self, guess: int):
        return guess == self.secret_bit


# =====================================================================
# 3. ATTACK DEMONSTRATIONS
# =====================================================================
def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """Helper to XOR two byte strings."""
    return bytes(a ^ b for a, b in zip(b1, b2))


def break_same_key():
    """
    Demonstrates the catastrophic failure of reusing the same key
    for both Encryption (CPA) and Authentication (MAC).
    """
    print("\n--- Initiating Same-Key Exploit ---")
    
    # 1. Setup the vulnerable game
    challenger = CCA_Challenger(same_key=True)
    
    m0 = b"ATTACK_AT_DAWN!!"
    m1 = b"RETREAT_NOW_PLZ!"
    
    # 2. Get the challenge ciphertext
    r_star, c_E_star, t_star = challenger.get_challenge(m0, m1)
    
    # 3. THE EXPLOIT:
    keystream = challenger.mac_oracle(r_star)
    
    # 4. Decrypt without knowing the key (using the stolen keystream)
    recovered_plaintext = xor_bytes(c_E_star, keystream[:len(c_E_star)])
    
    print(f"Message 0: {m0}")
    print(f"Message 1: {m1}")
    print(f"Recovered Plaintext: {recovered_plaintext}")
    
    # 5. Check if adversary wins
    adversary_guess = 0 if recovered_plaintext == m0 else 1
    if challenger.verify_guess(adversary_guess):
        print("[!] ADVERSARY WINS: Key reuse completely broke confidentiality.")
    else:
        print("Exploit failed (check your PA3/PA5 logic implementations).")


# class CPA_Oracle:
#     """Hides the key and simulates a remote CPA encryption service."""
#     def __init__(self):
#         self.k_E = os.urandom(16)
        
#     def encrypt(self, m: bytes):
#         return cpa_enc_logic(self.k_E, m)
        
#     def decrypt(self, r: bytes, c_E: bytes):
#         return cpa_dec_logic(self.k_E, r, c_E)



def demo_malleability_attack():
    """
    Demonstrates CPA malleability vs CCA security using proper Oracles.
    """
    print("\n--- Initiating Malleability Attack Demo ---")
    
    # Original message we want to corrupt (e.g., trying to change '100' to '900')
    m = b"SEND_100_DOLLARS"
    print(f"Original plaintext: {m}")
    

    # ==========================================
    # 1. CPA Attack (Malleable)
    # ==========================================
    cpa_server = CPA_Oracle()
    r, c_E = cpa_server.encrypt(m)    

    # changing 100 to 900.
    tampered_c_E = bytearray(c_E)
    tampered_c_E[5] ^= 0x08  
    
    # Adversary sends it back to the server to decrypt
    corrupted_m = cpa_server.decrypt(r, bytes(tampered_c_E))
    print(f"\n[!] CPA Decrypted (Tampered): {corrupted_m}")
    print("    -> SILENT FAILURE: Adversary successfully altered the message!")
    

    # ==========================================
    # 2. CCA Defense (Secure)
    # ==========================================
    cca_server = CCA_Challenger()

    r_cca, c_cca, t_cca = cca_server.encrypt_oracle(m)    

    tampered_c_cca = bytearray(c_cca)
    tampered_c_cca[5] ^= 0x08   # same as before
    
    cca_result = cca_server.decrypt_oracle(r_cca, bytes(tampered_c_cca), t_cca)
    
    if cca_result is None:
        print("\n[*] CCA Decrypted (Tampered): None (⊥)")
        print("    -> BLOCKED BY MAC: Attack detected and safely rejected.")
    else:
        print(f"\nCCA Failed to reject! Result: {cca_result}")

if __name__ == "__main__":
    # Run the demonstrations when the file is executed directly
    break_same_key()
    demo_malleability_attack()


##### TO DO : DEMO TO DEMONSTRATE MALLEABILITY ATTACKS ON CPA VS CCA.