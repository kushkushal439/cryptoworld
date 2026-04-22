# Implementations/PA_7.py

import struct

# =====================================================================
# 1. Merkle-Damgård Framework & Padding
# =====================================================================

def md_padding(message: bytes, block_size: int) -> bytes:
    """
    Applies MD-strengthening padding to a message.
    1. Append a '1' bit (0x80 in bytes).
    2. Append '0' bits until the length is congruent to (block_size - 8) modulo block_size.
    3. Append the original message length in bits as a 64-bit big-endian integer.
    """
    original_len_bits = len(message) * 8
    
    # 1. Append the '1' bit (0x80)
    padded_message = bytearray(message)
    padded_message.append(0x80)
    
    # 2. Append '0' bytes until we leave exactly 8 bytes for the length field
    # We want: len(padded_message) % block_size == block_size - 8
    while len(padded_message) % block_size != block_size - 8:
        padded_message.append(0x00)
        
    # 3. Append the 64-bit (8-byte) big-endian length
    padded_message.extend(struct.pack('>Q', original_len_bits))
    
    return bytes(padded_message)

class MerkleDamgard:
    def __init__(self, compress_fn, iv: bytes, block_size: int):
        """
        Generic MD Framework.
        :param compress_fn: A function f(chaining_value: bytes, block: bytes) -> bytes
        :param iv: The initial chaining value (e.g., 0^n)
        :param block_size: The size of the message blocks (in bytes)
        """
        self.compress_fn = compress_fn
        self.iv = iv
        self.block_size = block_size

    def hash(self, message: bytes) -> bytes:
        """
        Hashes an arbitrary-length message using the Merkle-Damgård transform.
        """
        # Step 1: Pad the message
        padded_msg = md_padding(message, self.block_size)
        
        # Step 2: Initialize the chaining value
        z = self.iv
        
        # Step 3: Process block by block
        for i in range(0, len(padded_msg), self.block_size):
            block = padded_msg[i : i + self.block_size]
            z = self.compress_fn(z, block)
            
        # Step 4: Output the final digest
        return z

# =====================================================================
# 2. Dummy Compression Plug-in (For Testing PA #7 in Isolation)
# =====================================================================

def xor_dummy_compress(chaining_val: bytes, block: bytes) -> bytes:
    """
    A toy compression function.
    Let IV/chaining_val be 4 bytes, and block be 8 bytes.
    We split the 8-byte block into two 4-byte halves and XOR them with the chaining value.
    h(z, B) = z ^ B_left ^ B_right
    """
    assert len(chaining_val) == 4, "Dummy chaining value must be 4 bytes"
    assert len(block) == 8, "Dummy block must be 8 bytes"
    
    b_left = block[:4]
    b_right = block[4:]
    
    result = bytearray(4)
    for i in range(4):
        result[i] = chaining_val[i] ^ b_left[i] ^ b_right[i]
        
    return bytes(result)

# =====================================================================
# 3. Collision Propagation Demo
# =====================================================================

def demo_collision_propagation():
    """
    Demonstrates that a collision in the underlying compression function 'h'
    propagates to a collision in the full Merkle-Damgård hash 'H'.
    """
    print("\n--- Merkle-Damgård Collision Propagation Demo ---")
    
    # Configure our toy MD hash: 4-byte IV, 8-byte blocks
    iv = b'\x00' * 4
    md_hasher = MerkleDamgard(compress_fn=xor_dummy_compress, iv=iv, block_size=8)
    
    # Let's craft two different 8-byte messages that deliberately collide in the dummy compression function.
    # Since h(z, B) = z ^ B_left ^ B_right:
    # If B1 = (0000, 0000), B_left ^ B_right = 0000
    # If B2 = (FFFF, FFFF), B_left ^ B_right = 0000
    # Thus, B1 and B2 will produce the exact same compression output!
    
    m1 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    m2 = b'\xff\xff\xff\xff\xff\xff\xff\xff'
    
    print(f"Message 1 (hex): {m1.hex()}")
    print(f"Message 2 (hex): {m2.hex()}")
    print(f"Are messages identical? {m1 == m2}")
    
    # 1. Prove they collide in the basic compression function
    comp_m1 = xor_dummy_compress(iv, m1)
    comp_m2 = xor_dummy_compress(iv, m2)
    print(f"\nCompression of M1: {comp_m1.hex()}")
    print(f"Compression of M2: {comp_m2.hex()}")
    print(f"Collision in 'h' successful? {comp_m1 == comp_m2}")
    
    # 2. Prove the collision survives the entire MD-Transform (including padding)
    hash_m1 = md_hasher.hash(m1)
    hash_m2 = md_hasher.hash(m2)
    print(f"\nFull MD Hash of M1: {hash_m1.hex()}")
    print(f"Full MD Hash of M2: {hash_m2.hex()}")
    print(f"Collision in 'H' successful? {hash_m1 == hash_m2}")
    print("\nConclusion: Breaking the compression function completely breaks the MD Hash.")

# =====================================================================
# 4. Boundary Cases Test
# =====================================================================

def test_boundary_cases():
    """Verify the framework handles varying message lengths gracefully."""
    print("\n--- Testing Boundary/Padding Cases ---")
    iv = b'\x00' * 4
    md_hasher = MerkleDamgard(compress_fn=xor_dummy_compress, iv=iv, block_size=8)
    
    msgs = {
        "Empty Message": b"",
        "Short Message": b"abc",
        "Exactly 1 Block": b"12345678",
        "Multi-Block": b"This message spans multiple blocks!"
    }
    
    for desc, msg in msgs.items():
        digest = md_hasher.hash(msg)
        print(f"{desc:<20} -> Digest: {digest.hex()} (Padded Len: {len(md_padding(msg, 8))} bytes)")

if __name__ == "__main__":
    test_boundary_cases()
    demo_collision_propagation()