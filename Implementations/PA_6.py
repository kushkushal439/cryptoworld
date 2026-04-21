import os
import random

from God import God
from Primitive_enums import Primitive

# Assumes you have a DLP module containing your base OWF instance
from CryptoPrimitives.DLP import dlp_owf 
from implementations.PA_5 import CPA_Scheme

def setup_primitive_instances():
    """Dynamically routes DLP through the God class to build the MAC."""
    cpa_server = CPA_Scheme()
    deity = God()
    mac_instance = deity.reduce(Primitive.OWF, Primitive.MAC, dlp_owf)
    return cpa_server, mac_instance

# =====================================================================
# 1. CORE CCA-SECURE LOGIC (Encrypt-then-MAC)
# =====================================================================

class CCA_Scheme:
    def __init__(self, cpa_instance=None, mac_instance=None):
        # If nothing is passed, spin up fresh default instances dynamically
        if cpa_instance is None or mac_instance is None:
            default_cpa, default_mac = setup_primitive_instances()
            self.cpa = cpa_instance or default_cpa
            self.mac = mac_instance or default_mac
        else:
            self.cpa = cpa_instance
            self.mac = mac_instance

    def CCA_Enc(self, k_E: bytes, k_M: bytes, m: bytes):
        """Matches spec: CCA_Enc(kE, kM, m) -> (c, t)"""
        r, c_E = self.cpa.encrypt(k_E, m)

        # MAC the ciphertext (often requires appending r depending on your exact spec)
        ciphertext_payload = r + c_E
        t = self.mac.tag(k_M, ciphertext_payload)

        return (r, c_E), t

    def CCA_Dec(self, k_E: bytes, k_M: bytes, c: tuple, t: bytes):
        """Matches spec: CCA_Dec(kE, kM, c, t) -> m or None"""
        r, c_E = c
        ciphertext_payload = r + c_E

        # 1. Verify MAC first!
        if not self.mac.vrfy(k_M, ciphertext_payload, t):
            return None

        # 2. Decrypt only if MAC is valid
        return self.cpa.decrypt(k_E, r, c_E)


# =====================================================================
# 2. IND-CCA2 CHALLENGER GAME STATE
# =====================================================================

class CCA_Challenger:
    def __init__(self, cpa_instance = cpa_default, mac_instance = mac_default, same_key=False):
        """
        Initializes the game. 
        If same_key=True, it intentionally introduces the PA#6 Key Separation vulnerability.
        """
        self.k_E = os.urandom(16)
        self.k_M = self.k_E if same_key else os.urandom(16)
        
        self.cca_scheme = CCA_Scheme(cpa_instance, mac_instance)

        self.challenge_ciphertext = None
        self.secret_bit = random.choice([0, 1])

    def encrypt_oracle(self, m: bytes):
        """Allows adversary to get encryptions of arbitrary messages."""
        return self.cca_scheme.CCA_Enc(self.k_E, self.k_M, m)

    def mac_oracle(self, payload: bytes):
        """
        Adversary has access to a MAC oracle in a standard game.
        This is used to demonstrate the same-key exploit.
        """
        return self.cca_scheme.mac.tag(self.k_M, payload)

    def decrypt_oracle(self, c: tuple, t: bytes):
        """
        Allows adversary to decrypt anything EXCEPT the challenge ciphertext.
        """
        query_tuple = (c, t)

        if self.challenge_ciphertext and query_tuple == self.challenge_ciphertext:
            return "REJECT: Cannot query the challenge ciphertext!"

        return self.cca_scheme.CCA_Dec(self.k_E, self.k_M, c, t)

    def get_challenge(self, m0: bytes, m1: bytes):
        """Adversary submits two messages, gets one back encrypted."""
        if len(m0) != len(m1):
            raise ValueError("Messages must be the same length")
            
        mb = m1 if self.secret_bit == 1 else m0
        
        # Encrypt and lock the state
        c, t = self.cca_scheme.CCA_Enc(self.k_E, self.k_M, mb)
        self.challenge_ciphertext = (c, t)
        
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
    
    cpa_server, mac_instance = setup_primitive_instances()
    
    # 1. Setup the vulnerable game
    challenger = CCA_Challenger(cpa_server, mac_instance, same_key=True)
    
    m0 = b"ATTACK_AT_DAWN!!"
    m1 = b"RETREAT_NOW_PLZ!"
    
    # 2. Get the challenge ciphertext
    c_star, t_star = challenger.get_challenge(m0, m1)
    r_star, c_E_star = c_star
    
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

def demo_malleability_attack():
    """
    Demonstrates CPA malleability vs CCA security using proper Oracles.
    """
    print("\n--- Initiating Malleability Attack Demo ---")
    
    # Original message we want to corrupt
    m = b"SEND_100_DOLLARS"
    print(f"Original plaintext: {m}")
    
    cpa_server, mac_instance = setup_primitive_instances()

    # ==========================================
    # 1. CPA Attack (Malleable)
    # ==========================================
    r, c_E = cpa_server.encrypt(m)    

    # Changing 100 to 900.
    tampered_c_E = bytearray(c_E)
    tampered_c_E[5] ^= 0x08  
    
    # Adversary sends it back to the server to decrypt
    corrupted_m = cpa_server.decrypt(r, bytes(tampered_c_E))
    print(f"\n[!] CPA Decrypted (Tampered): {corrupted_m}")
    print("    -> SILENT FAILURE: Adversary successfully altered the message!")
    
    # ==========================================
    # 2. CCA Defense (Secure)
    # ==========================================
    cca_server = CCA_Challenger(cpa_server, mac_instance)

    c_cca, t_cca = cca_server.encrypt_oracle(m)    
    r_cca, c_E_cca = c_cca

    tampered_c_E_cca = bytearray(c_E_cca)
    tampered_c_E_cca[5] ^= 0x08   # Exact same flip
    
    tampered_c_cca = (r_cca, bytes(tampered_c_E_cca))
    
    cca_result = cca_server.decrypt_oracle(tampered_c_cca, t_cca)
    
    if cca_result is None:
        print("\n[*] CCA Decrypted (Tampered): None (⊥)")
        print("    -> BLOCKED BY MAC: Attack detected and safely rejected.")
    else:
        print(f"\nCCA Failed to reject! Result: {cca_result}")

if __name__ == "__main__":
    break_same_key()
    demo_malleability_attack()