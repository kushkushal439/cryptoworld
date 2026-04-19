class CPA_Oracle:
    """Hides the key and simulates a remote CPA encryption service."""
    def __init__(self):
        self.k_E = os.urandom(16)
        
    def encrypt(self, m: bytes):
        return cpa_enc_logic(self.k_E, m)
        
    def decrypt(self, r: bytes, c_E: bytes):
        return cpa_dec_logic(self.k_E, r, c_E)