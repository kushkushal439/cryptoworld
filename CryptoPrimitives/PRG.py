from .base import CryptoPrimitive
from Primitive_enums import Primitive
from typing import Callable

class PRG(CryptoPrimitive):
    def __init__(self, logic_func: Callable):
        super().__init__(Primitive.PRG)
        self.logic_func = logic_func

    def generate(self, seed, length, **kwargs):
        return self.logic_func(seed, length, **kwargs)