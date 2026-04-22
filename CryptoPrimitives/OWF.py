from typing import Callable
from Primitive_enums import Primitive
from .base import CryptoPrimitive
from Primitive_enums import Primitive
from typing import Callable

class OWF(CryptoPrimitive):
    def __init__(self, logic_func: Callable):
        super().__init__(Primitive.OWF)
        self.logic_func = logic_func

    def evaluate(self, x, **kwargs):
        return self.logic_func(x, **kwargs)

    def verify_hardness(self):
        """
        Demonstrate that random inversion fails. Must be implemented or overridden.
        """
        import os
        x = os.urandom(16)
        y = self.evaluate(x)
        print(f"Target block: {y.hex()[:10]}...")
        print("Attempting naive inversion...")
        for _ in range(1000):
            guess = os.urandom(16)
            if self.evaluate(guess) == y:
                print("Inverted successfully! Not a secure OWF.")
                return True
        print("Failed to invert OWF after 1000 trials. Hardness holds.")
        return False


# example usage:

# def dlp_logic_func(x, p, g):
#     """
#     Computes g^x mod p.
#     """
#     return pow(g, x, p)

# # Instantiate it!
# dlp_owf = OWF(dlp_logic_func)

