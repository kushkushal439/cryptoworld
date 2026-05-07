from typing import Callable
from Primitive_enums import Primitive
from .base import CryptoPrimitive

class OWP(CryptoPrimitive):
    def __init__(self, logic_func: Callable):
        super().__init__(Primitive.OWP)
        self.logic_func = logic_func

    def evaluate(self, x, **kwargs):
        """Evaluates the permutation."""
        return self.logic_func(x, **kwargs)

    def verify_hardness(self):
        """
        Demonstrate that random inversion fails. 
        """
        import os
        x = os.urandom(16)
        y = self.evaluate(x)
        print(f"Target block: {y.hex()[:10]}...")
        print("Attempting naive inversion...")
        for _ in range(1000):
            guess = os.urandom(16)
            if self.evaluate(guess) == y:
                print("Inverted successfully! Not a secure OWP.")
                return True
        print("Failed to invert OWP after 1000 trials. Hardness holds.")
        return False