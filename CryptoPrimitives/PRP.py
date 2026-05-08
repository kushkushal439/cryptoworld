from typing import Callable, Optional, Any
from .base import CryptoPrimitive
from Primitive_enums import Primitive

class PRP(CryptoPrimitive):
    def __init__(self, 
                 underlying_primitive: Optional[CryptoPrimitive], 
                 forward_logic: Callable, 
                 inverse_logic: Callable,
                 block_size: int):
        super().__init__(Primitive.PRP)
        self.underlying = underlying_primitive 
        self.forward_logic = forward_logic
        self.inverse_logic = inverse_logic
        self.block_size = block_size 

    def evaluate(self, key: bytes, query: Any) -> bytes:
        """
        Evaluates the permutation in the forward direction (e.g., Encryption).
        """
        if self.underlying is not None:
            return self.forward_logic(self.underlying, key, query)
        else:
            return self.forward_logic(key, query)

    def inverse(self, key: bytes, query: Any) -> bytes:
        """
        Evaluates the permutation in the backward direction (e.g., Decryption).
        """
        if self.underlying is not None:
            return self.inverse_logic(self.underlying, key, query)
        else:
            return self.inverse_logic(key, query)