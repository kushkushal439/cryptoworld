from flask import Blueprint, request, jsonify
from Implementations.PA_8 import generate_safe_prime, DLP_Hash, mod_inverse
import random
import math

dlp_api = Blueprint('dlp_api', __name__)

# Global instances for the demo to prevent regenerating primes on every request
print("Generating Toy 16-bit Safe Prime...")
# 1. Toy parameters (16-bit output, for collision demo)
toy_p, toy_q = generate_safe_prime(16)
toy_g = pow(random.randint(2, toy_p-2), 2, toy_p)
toy_alpha = random.randint(1, toy_q - 1)
toy_h_hat = pow(toy_g, toy_alpha, toy_p)
toy_block_size = (toy_q.bit_length() + 7) // 8
toy_hasher = DLP_Hash(toy_p, toy_q, toy_g, toy_h_hat, block_size=toy_block_size)

print("Generating Full 64-bit Safe Prime (This might take a minute)...")
# 2. Full parameters (64-bit output)
full_p, full_q = generate_safe_prime(64)
full_g = pow(random.randint(2, full_p-2), 2, full_p)
full_alpha = random.randint(1, full_q - 1)
full_h_hat = pow(full_g, full_alpha, full_p)
full_block_size = (full_q.bit_length() + 7) // 8
full_hasher = DLP_Hash(full_p, full_q, full_g, full_h_hat, block_size=full_block_size)
print("Primes Generated!")

@dlp_api.route('/hash', methods=['POST'])
def hash_message():
    data = request.json
    message_str = data.get('message', '')
    
    msg_bytes = message_str.encode('utf-8')
    
    # Compute hashes
    toy_digest = toy_hasher.hash(msg_bytes)
    full_digest = full_hasher.hash(msg_bytes)
    
    return jsonify({
        "status": "success", 
        "toy_hash": toy_digest.hex(),
        "full_hash": full_digest.hex()
    })

@dlp_api.route('/collision', methods=['POST'])
def collision_hunt():
    seen = {}
    tries = 0
    collision_found = False
    
    while not collision_found and tries < 10000:  # Safety cap
        tries += 1
        x = random.randint(0, toy_q - 1)
        y = random.randint(0, toy_q - 1)
        
        # h(x,y) = g^x * h_hat^y mod p
        res = (pow(toy_g, x, toy_p) * pow(toy_h_hat, y, toy_p)) % toy_p
        
        if res in seen:
            x_old, y_old = seen[res]
            if (x, y) != (x_old, y_old):
                delta_x = (x_old - x) % toy_q
                delta_y = (y - y_old) % toy_q
                
                if math.gcd(delta_y, toy_q) == 1:
                    delta_y_inv = mod_inverse(delta_y, toy_q)
                    recovered_alpha = (delta_x * delta_y_inv) % toy_q
                    
                    return jsonify({
                        "status": "success",
                        "tries": tries,
                        "x1": x_old, "y1": y_old,
                        "x2": x, "y2": y,
                        "output": res,
                        "recovered_alpha": recovered_alpha,
                        "target_tries": int(math.sqrt(toy_q))
                    })
        seen[res] = (x, y)
        
    return jsonify({"status": "error", "message": "No collision found within cap"})
