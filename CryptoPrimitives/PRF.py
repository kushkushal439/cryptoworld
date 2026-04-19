from typing import Callable, Optional, Any
from .base import CryptoPrimitive
from Primitive_enums import Primitive

class PRF(CryptoPrimitive):
    def __init__(self, 
                 underlying_primitive: Optional[CryptoPrimitive], 
                 logic_func: Callable, 
                 block_size: int):
        super().__init__(Primitive.PRF)
        self.underlying = underlying_primitive 
        self.logic_func = logic_func
        
        # We explicitly require block_size to prevent AES/GGM silent errors.
        # AES = 16 bytes. GGM (n-bit depth) = n // 8 bytes.
        self.block_size = block_size 


        # TO IMPLEMENTED PRF FROM BASE AES: The external user calls something like
        # Base_PRF =  PRF(None, aes_prf_logic, block_size=16). He wont be using God conversion

    def evaluate(self, key: bytes, query: Any) -> bytes:
        """
        Evaluates the PRF on a given query using the provided key.
        
        :param key: The secret key (or GGM root seed).
        :param query: The input to evaluate (bytes for AES, bit-string for GGM).
        :return: The pseudorandom output as bytes.
        """
        if self.underlying is not None:
            # GGM Tree route: Inject the underlying PRG's evaluate function
            return self.logic_func(self.underlying.evaluate, key, query)
        else:
            # Direct AES route: No underlying primitive to inject
            return self.logic_func(key, query)