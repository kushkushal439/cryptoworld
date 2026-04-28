from enum import Enum, auto

class Primitive(Enum):
    OWF = auto()   # One-Way Function
    PRG = auto()   # Pseudorandom Generator
    PRF = auto()   # Pseudorandom Function
    OWP = auto()   # One-Way Permutation
    PRP = auto()   # Pseudorandom Permutation
    MAC = auto()   # Message Authentication Code
    CRHF = auto()  # Collision-Resistant Hash Function
    HMAC = auto()  # Hash-based MAC
    CBC = auto()   # Cipher Block Chaining Mode
    OFB = auto()   # Output Feedback Mode
    CTR = auto()   # Counter Mode