from typing import Callable
from Primitive_enums import Primitive

class CryptoPrimitive:
    def __init__(self, p_type: Primitive):
        self.p_type = p_type