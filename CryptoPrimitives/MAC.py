from .base import CryptoPrimitive
from Primitive_enums import Primitive
from Implementations.PA_5 import prf_mac_logic, cbc_mac_logic

class MAC(CryptoPrimitive):
    def __init__(self, underlying_primitive, mode="CBC"):
        super().__init__(Primitive.MAC)
        self.underlying = underlying_primitive # This will be the PRF (or Hash for HMAC)
        self.mode = mode.upper()

    def tag(self, key, message):
        if self.mode == "PRF":
            return prf_mac_logic(self.underlying.evaluate, key, message)
        elif self.mode == "CBC":
            # GGM PRF doesn't have a strict block size, so default to 16 bytes
            bs = self.underlying.block_size if self.underlying.block_size else 16
            
            return cbc_mac_logic(self.underlying.evaluate, key, message, block_size=bs)
        elif self.mode == "HMAC":
            from Implementations.PA_10 import HMAC
            return HMAC(key, message, self.underlying)  
        else:
            raise ValueError(f"Unknown MAC mode: {self.mode}")

    def vrfy(self, key, message, provided_tag):
        return self.tag(key, message) == provided_tag