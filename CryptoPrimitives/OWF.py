from .base import CryptoPrimitive

class OWF(CryptoPrimitive):
    def __init__(self, logic_func: Callable):
        super().__init__(Primitive.OWF)
        self.logic_func = logic_func

    def evaluate(self, x, **kwargs):
        return self.logic_func(x, **kwargs)

# example usage:

# def dlp_logic_func(x, p, g):
#     """
#     Computes g^x mod p.
#     """
#     return pow(g, x, p)

# # Instantiate it!
# dlp_owf = OWF(dlp_logic_func)

