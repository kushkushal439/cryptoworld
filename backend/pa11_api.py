from flask import Blueprint, request, jsonify
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Implementations.PA_11 import generate_dh_parameters, square_and_multiply
from Implementations.PA_13 import is_prime

pa11_api = Blueprint('pa11_api', __name__)

# Global cache for the toy parameters to avoid generating on every request
_cached_params = None

def get_params():
    global _cached_params
    if not _cached_params:
        p, q, g = generate_dh_parameters(32)
        _cached_params = {
            "p": p,
            "q": q,
            "g": g,
            "p_hex": hex(p),
            "q_hex": hex(q),
            "g_hex": hex(g)
        }
    return _cached_params

@pa11_api.route('/params', methods=['GET'])
def params():
    return jsonify({
        "status": "success",
        "params": get_params()
    })

@pa11_api.route('/exchange', methods=['POST'])
def exchange():
    data = request.json or {}
    
    try:
        p = int(data.get('p', get_params()['p']), 16) if isinstance(data.get('p'), str) else int(data.get('p', get_params()['p']))
        g = int(data.get('g', get_params()['g']), 16) if isinstance(data.get('g'), str) else int(data.get('g', get_params()['g']))
        
        a = int(str(data.get('a')), 16)
        b = int(str(data.get('b')), 16)
        
        is_mitm = data.get('is_mitm', False)
        
        # 1. Compute Public Keys
        A = square_and_multiply(g, a, p)
        B = square_and_multiply(g, b, p)
        
        result = {
            "status": "success",
            "A_hex": hex(A),
            "B_hex": hex(B)
        }
        
        if not is_mitm:
            # Honest exchange
            K_Alice = square_and_multiply(B, a, p)
            K_Bob = square_and_multiply(A, b, p)
            
            result["K_Alice_hex"] = hex(K_Alice)
            result["K_Bob_hex"] = hex(K_Bob)
        else:
            # MITM Attack
            e_val = data.get('e')
            if e_val is None:
                return jsonify({"status": "error", "message": "Eve's private key 'e' is required for MITM."}), 400
                
            e = int(str(e_val), 16)
            
            # Eve computes her public spoofed keys (which are just g^e)
            A_prime = square_and_multiply(g, e, p)
            B_prime = square_and_multiply(g, e, p)
            
            # Alice and Bob compute their shared secrets with what they think is the other party
            K_Alice = square_and_multiply(B_prime, a, p)
            K_Bob = square_and_multiply(A_prime, b, p)
            
            # Eve computes both shared secrets
            K_Eve_Alice = square_and_multiply(A, e, p)
            K_Eve_Bob = square_and_multiply(B, e, p)
            
            result["A_prime_hex"] = hex(A_prime)
            result["B_prime_hex"] = hex(B_prime)
            result["K_Alice_hex"] = hex(K_Alice)
            result["K_Bob_hex"] = hex(K_Bob)
            result["K_Eve_Alice_hex"] = hex(K_Eve_Alice)
            result["K_Eve_Bob_hex"] = hex(K_Eve_Bob)
            
        return jsonify(result)
        
    except ValueError as err:
        return jsonify({"status": "error", "message": f"Invalid input format. Must be hex strings. {err}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
