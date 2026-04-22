import os
import random

# Assume implementations exist based on the instructions
from Implementations.PA_12 import rsa_keygen, rsa_sign_raw, rsa_verify_raw
from Implementations.PA_8 import DLP_Hash

# =====================================================================
# 1. CORE RSA SIGNATURE LOGIC (Hash-then-Sign)
# =====================================================================

def Sign(sk: tuple, m: bytes) -> int:
    """
    Hash-then-Sign signature formulation.
    Sign(sk, m) = H(m)^d mod N
    """
    h_m = DLP_Hash(m)
    sigma = rsa_sign_raw(sk, h_m)
    return sigma

def Verify(vk: tuple, m: bytes, sigma: int) -> bool:
    """
    Validation condition: sigma^e mod N == H(m)
    """
    h_m = DLP_Hash(m)
    verification_check = rsa_verify_raw(vk, sigma)
    return verification_check == h_m

# =====================================================================
# 2. RAW RSA SIGNATURE (Vulnerable)
# =====================================================================

def sign_raw(sk: tuple, m_int: int) -> int:
    """Signs an integer directly. m^d mod N."""
    return rsa_sign_raw(sk, m_int)

def verify_raw(vk: tuple, m_int: int, sigma: int) -> bool:
    """Verifies a raw signature. sigma^e mod N == m."""
    return rsa_verify_raw(vk, sigma) == m_int

# =====================================================================
# 3. ATTACK DEMONSTRATIONS 
# =====================================================================

def demonstrate_multiplicative_forgery():
    """
    Show that without hashing, an adversary can forge a signature 
    on m1 * m2 given signatures on m1 and m2.
    """
    print("\n--- Initiating Multiplicative Homomorphism Attack (Raw RSA) ---")
    
    vk, sk = rsa_keygen(1024)
    N, e = vk
    
    m1 = 12345
    m2 = 67890
    
    sigma_1 = sign_raw(sk, m1)
    sigma_2 = sign_raw(sk, m2)
    
    print(f"Server issued signature for m1 ({m1}): {sigma_1}")
    print(f"Server issued signature for m2 ({m2}): {sigma_2}")
    
    # Adversary generates a valid signature for m3 = (m1 * m2) mod N
    m3_forged = (m1 * m2) % N
    sigma_forged = (sigma_1 * sigma_2) % N
    
    print(f"Adversary constructs target message m3 = (m1*m2): {m3_forged}")
    print(f"Adversary constructs targeted signature (s1*s2): {sigma_forged}")
    
    # Validate the forged signature seamlessly worked
    valid = verify_raw(vk, m3_forged, sigma_forged)
    
    if valid:
        print("[!] ADVERSARY WINS: Forgery completely bypassed verification.")
    else:
        print("Failure in verifying attack.")


class EUFCMA_Game:
    def __init__(self):
        """Sets up the game with fresh RSA keys."""
        self.vk, self.sk = rsa_keygen(1024)
        self.signed_messages = set()
        
    def signing_oracle(self, m: bytes) -> int:
        """Adversary requests signatures for arbitrary messages"""
        self.signed_messages.add(m)
        return Sign(self.sk, m)
        
    def verify_forgery(self, m_star: bytes, sigma_star: int) -> bool:
        """
        Validates if the adversary successfully forged a completely new signature.
        """
        if m_star in self.signed_messages:
            print("REJECT: Adversary must select a message not queried before (m_star not in History).")
            return False
            
        print("Evaluating forgery...")
        return Verify(self.vk, m_star, sigma_star)

def demo_euf_cma():
    """
    Implement the signing oracle game to test if the adversary can forge 
    a proper hash-then-sign payload.
    """
    print("\n--- EUF-CMA Game Simulation (Hash-then-Sign) ---")
    game = EUFCMA_Game()
    
    print("Adversary generates 50 valid signatures from the Oracle...")
    queries = [os.urandom(16) for _ in range(50)]
    for q in queries:
        game.signing_oracle(q)
        
    # Adversary tries to forge a signature for a new message
    m_challenge = b"GIVE_ME_ACCESS"
    
    print(f"Adversary attempts to forge signature for new message: {m_challenge}")
    
    # 1. Random Guess Forgery (Unlikely to succeed given Hash and Modulo constraint)
    random_sigma = random.getrandbits(1024)
    print("Attempt 1: Random modular mapping...")
    
    if game.verify_forgery(m_challenge, random_sigma):
        print("Successfully forged!")
    else:
        print("[*] Verification Failed! The proper Hash-then-Sign construction held.")


# =====================================================================
# 4. INTERACTIVE DEMONSTRATION SIMULATION
# =====================================================================

def interactive_demo_simulation():
    """
    Simulates the interactive demo sequence.
    """
    print("\n--- Interactive PA #15 Demo Scenario ---")
    
    vk, sk = rsa_keygen(1024)
    N, e = vk
    
    message = b"CS8.401_PA15_Is_Awesome!"
    print(f"[1] Original Message: {message.decode()}")
    
    # Sign 
    sigma = Sign(sk, message)
    print(f"[2] Signature Computed (Hex Hash-then-Sign): {hex(sigma)[:30]}...")
    
    # Verify Valid
    is_valid = Verify(vk, message, sigma)
    print(f"[3] Honest Verification Result: {'Valid' if is_valid else 'Invalid'}")
    
    # Tamper
    tampered_message = b"CS8.401_PA15_Is_Awesone!" # i flipped to n
    print(f"[4] Tampered Message Detected: {tampered_message.decode()}")
    
    is_valid_tampered = Verify(vk, tampered_message, sigma)
    print(f"[5] Tampered Verification Result: {'Valid' if is_valid_tampered else 'Invalid'}")
    assert not is_valid_tampered

if __name__ == "__main__":
    demonstrate_multiplicative_forgery()
    demo_euf_cma()
    interactive_demo_simulation()