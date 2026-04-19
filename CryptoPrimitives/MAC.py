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
            return cbc_mac_logic(self.underlying.evaluate, key, message, block_size=self.underlying.block_size)
        elif self.mode == "HMAC":
            raise NotImplementedError("HMAC is scheduled for PA #10!")
        else:
            raise ValueError(f"Unknown MAC mode: {self.mode}")

    def vrfy(self, key, message, provided_tag):
        return self.tag(key, message) == provided_tag