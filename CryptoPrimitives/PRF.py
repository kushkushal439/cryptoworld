# CryptoPrimitives/PRF.py

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
        self.block_size = block_size 

    def evaluate(self, key: bytes, query: Any) -> bytes:
        if self.underlying is not None:
            # Pass the entire underlying instance to the logic function
            return self.logic_func(self.underlying, key, query)
        else:
            return self.logic_func(key, query)