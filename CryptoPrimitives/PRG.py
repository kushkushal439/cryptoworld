from typing import Callable
from Primitive_enums import Primitive
from .base import CryptoPrimitive
from Primitive_enums import Primitive
from typing import Callable

class PRG(CryptoPrimitive):
    def __init__(self, logic_func: Callable):
        super().__init__(Primitive.PRG)
        self.logic_func = logic_func

    def generate(self, seed, length, **kwargs):
        return self.logic_func(seed, length, **kwargs)

    def seed(self, s: bytes):
        """PA1 specific interface initialization."""
        self._current_seed = s
        self._bit_buffer = ""

    def next_bits(self, n: int) -> str:
        """PA1 specific interface implementation."""
        if not hasattr(self, '_current_seed'):
            raise ValueError("PRG not seeded!")
            
        out_bytes = self.generate(self._current_seed, n)
        # Update seed for next call (using the PRG itself to refresh its seed is simple)
        # We can just generate n + len(seed) bits and use the last part as the new seed.
        # But wait, hill_prg_logic provides n+l bits. The standard way is just to advance the base seed.
        # Let's generate a larger chunk and slice it for simplicity here.
        new_seed_bytes = self.generate(self._current_seed, len(self._current_seed) * 8 + n)
        self._current_seed = new_seed_bytes[-len(self._current_seed):]

        # Convert to bit string
        bits = []
        for b in out_bytes:
            for i in range(8):
                bits.append(str((b >> (7 - i)) & 1))
                
        return "".join(bits[:n])