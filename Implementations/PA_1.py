# implementations/PA1.py
from CryptoPrimitives.PRG import PRG

def convert_owf_to_prg(owf_instance):
    """Wraps the HILL logic inside a PRG container."""
    # Notice how we bind the required owf_instance via a lambda/closure
    bound_logic = lambda seed, length: hill_prg_logic(seed, length, owf_instance)
    return PRG(bound_logic)