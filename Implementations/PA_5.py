from CryptoPrimitives.PRF import PRF
# from CryptoPrimitives.MAC import MAC

def prf_mac_logic(prf_eval_func, key, message):
    """PA #5: Fixed-length PRF-MAC logic"""
    # Simply pass the message through the PRF
    return prf_eval_func(key, message)

def cbc_mac_logic(prf_eval_func, key: bytes, message: bytes, block_size: int = 16) -> bytes:
    """
    PA #5: Variable-length CBC-MAC logic.
    
    :param prf_eval_func: The evaluate function of the underlying PRF/AES.
    :param key: The MAC key (bytes).
    :param message: The arbitrary-length message to authenticate (bytes).
    :param block_size: The block size of the underlying PRF (typically 16 bytes for AES).
    :return: The final MAC tag (bytes).
    """
    
    # 1. Pad the message (PKCS#7 Padding)
    # This ensures the message is a perfect multiple of the block_size.
    # It pads by appending bytes with the value of the number of padding bytes needed.
    pad_len = block_size - (len(message) % block_size)
    padded_message = message + bytes([pad_len] * pad_len)
    
    # 2. Initialize the chaining value (t_0) to an IV of all zeros
    t = b'\x00' * block_size
    
    # 3. Process the message block by block
    for i in range(0, len(padded_message), block_size):
        # Extract the current block
        block = padded_message[i : i + block_size]
        
        # XOR the current block with the previous tag 't'
        xored_block = bytes(a ^ b for a, b in zip(t, block))
        
        # Evaluate the PRF on the XORed block to get the new tag
        t = prf_eval_func(key, xored_block)
        
    # 4. Output the final chaining value as the tag
    return t


def hmac():
    raise NotImplementedError("HMAC is scheduled for PA #10!")

import os

def euf_cma_demo(mac_instance):
    print("=== EUF-CMA Forgery Game ===")
    
    # The Challenger generates a secret key
    secret_key = os.urandom(16)
    oracle_history = {} # Stores {message: tag}
    
    print("[+] Oracle is ready. Adversary is requesting 50 tags...")
    
    # PHASE 1: Adversary queries the Oracle 50 times
    for i in range(50):
        # Generate a random 16-byte message
        m = os.urandom(16) 
        t = mac_instance.tag(secret_key, m)
        oracle_history[m] = t
        
    print(f"[+] Adversary collected {len(oracle_history)} valid (message, tag) pairs.")
    
    # PHASE 2: The Forgery Attempt
    # The adversary chooses a NEW message not in the history
    m_star = b"Transfer $1,000,000 to Eve!!!"
    assert m_star not in oracle_history, "Message must be new!"
    
    print(f"\n[!] Adversary attempting to forge tag for: {m_star}")
    
    # Naive Strategy 1: Completely random guess
    random_tag = os.urandom(16)
    
    # Naive Strategy 2: Try to reuse a tag from a completely different message
    stolen_tag = list(oracle_history.values())[0]
    
    # The Challenger verifies the attempts
    success_random = mac_instance.vrfy(secret_key, m_star, random_tag)
    success_stolen = mac_instance.vrfy(secret_key, m_star, stolen_tag)
    
    print(f"    -> Result of Random Guess: {'SUCCESS' if success_random else 'REJECTED'}")
    print(f"    -> Result of Stolen Tag:   {'SUCCESS' if success_stolen else 'REJECTED'}")
    print("=== Game Over ===\n")




def length_extension_demo(compression_func, block_size=16):
    print("=== Length-Extension Attack on Naive H(k||m) ===")
    
    # 1. Setup
    secret_key = b"secret_k"
    original_message = b"data=100"
    
    # The Honest Sender computes the naive MAC
    payload = secret_key + original_message
    
    # (Simulating PA #7 Merkle-Damgård processing)
    # We assume the payload fits perfectly in one block for this simple demo
    iv = b'\x00' * block_size 
    padded_payload = payload.ljust(block_size, b'\x00') 
    
    # The tag is the output of the compression function
    valid_tag = compression_func(iv, padded_payload)
    print(f"[+] Honest sender sends message: '{original_message.decode()}'")
    print(f"[+] Honest sender sends tag:     {valid_tag.hex()}")
    
    # 2. The Attack (Adversary intercepts message and tag)
    print("\n[!] Adversary intercepts the message and tag!")
    malicious_suffix = b"&admin=1"
    padded_suffix = malicious_suffix.ljust(block_size, b'\x00')
    
    # THE VULNERABILITY:
    # The adversary uses the intercepted tag as the NEW internal state (IV)
    # and compresses the malicious suffix. They DO NOT need the secret key.
    forged_tag = compression_func(valid_tag, padded_suffix)
    
    # The new message is the original + the padding that was implicitly added + the suffix
    forged_message = original_message + (b'\x00' * (block_size - len(payload))) + malicious_suffix
    
    print(f"[!] Adversary forged message:    {forged_message}")
    print(f"[!] Adversary forged tag:        {forged_tag.hex()}")
    
    # 3. The Verification (The Server receives the forgery)
    # The server computes H(secret_key || forged_message)
    server_payload = secret_key + forged_message
    
    # Server processes block 1
    server_block_1 = server_payload[:block_size]
    server_state = compression_func(iv, server_block_1)
    
    # Server processes block 2
    server_block_2 = server_payload[block_size:block_size*2]
    server_final_tag = compression_func(server_state, server_block_2)
    
    print("\n[?] Server verifying the forged message...")
    if server_final_tag == forged_tag:
        print("[!] CRITICAL FAILURE: Server accepted the forged message!")
        print("    This is why we need the HMAC double-hash structure.")
    else:
        print("[-] Forgery failed.")
    print("================================================\n")






from Implementations.PA_3 import CPA_Scheme
