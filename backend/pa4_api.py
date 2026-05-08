# backend/pa4_api.py

from flask import Blueprint, request, jsonify
import os
import base64

# It's crucial that the path is correct to import from the parent directory
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Implementations.PA_4 import Encrypt, Decrypt, flip_bit_in_ciphertext, BLOCK_SIZE, CBC_Enc_manual, OFB_Enc_Dec

pa4_api = Blueprint('pa4_api', __name__)

# Use a fixed key for the demo for simplicity and consistency
DEMO_KEY = os.urandom(16)

def split_into_blocks(data, block_size):
    """Helper to split data into a list of hex strings."""
    return [data[i:i+block_size].hex() for i in range(0, len(data), block_size)]

# CORRECTED ROUTE: from '/pa4/encrypt' to '/encrypt'
@pa4_api.route('/encrypt', methods=['POST'])
def pa4_encrypt():
    data = request.get_json()
    mode = data.get('mode')
    plaintext_str = data.get('plaintext')
    
    if not all([mode, plaintext_str]):
        return jsonify({"error": "Missing mode or plaintext"}), 400
        
    plaintext_bytes = plaintext_str.encode('utf-8')
    
    try:
        iv_or_nonce, ciphertext = Encrypt(mode, DEMO_KEY, plaintext_bytes)
        
        trace = {
            "key": DEMO_KEY.hex(),
            "iv_or_nonce": iv_or_nonce.hex(),
            "plaintext_blocks": split_into_blocks(plaintext_bytes, BLOCK_SIZE),
            "ciphertext_blocks": split_into_blocks(ciphertext, BLOCK_SIZE)
        }
        
        return jsonify({
            "iv_or_nonce": iv_or_nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "trace": trace
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# CORRECTED ROUTE: from '/pa4/flip-bit-and-decrypt' to '/flip-bit-and-decrypt'
@pa4_api.route('/flip-bit-and-decrypt', methods=['POST'])
def pa4_flip_and_decrypt():
    data = request.get_json()
    mode = data.get('mode')
    ciphertext_hex = data.get('ciphertext')
    iv_or_nonce_hex = data.get('iv_or_nonce')
    block_index = data.get('block_index')
    bit_index = data.get('bit_index')

    if not all([mode, ciphertext_hex, iv_or_nonce_hex, isinstance(block_index, int), isinstance(bit_index, int)]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        iv_or_nonce = bytes.fromhex(iv_or_nonce_hex)
        flipped_ciphertext = flip_bit_in_ciphertext(ciphertext, block_index, bit_index)
        corrupted_plaintext = Decrypt(mode, DEMO_KEY, iv_or_nonce, flipped_ciphertext)

        return jsonify({
            "flipped_ciphertext": flipped_ciphertext.hex(),
            "corrupted_plaintext": corrupted_plaintext.hex(),
            "corrupted_plaintext_ascii": corrupted_plaintext.decode('utf-8', errors='replace')
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# CORRECTED ROUTE: from '/pa4/reuse-iv' to '/reuse-iv'
@pa4_api.route('/reuse-iv', methods=['POST'])
def pa4_reuse_iv():
    data = request.get_json()
    m1_str = data.get('m1')
    m2_str = data.get('m2')

    if not all([m1_str, m2_str]):
        return jsonify({"error": "Missing m1 or m2"}), 400

    iv_reuse = os.urandom(BLOCK_SIZE)
    m1 = m1_str.encode('utf-8')
    m2 = m2_str.encode('utf-8')

    try:
        from Implementations.PA_4 import pad
        c1, _ = CBC_Enc_manual(DEMO_KEY, pad(m1), iv_reuse)
        c2, _ = CBC_Enc_manual(DEMO_KEY, pad(m2), iv_reuse)
        ofb_c1 = OFB_Enc_Dec(DEMO_KEY, iv_reuse, m1)
        ofb_c2 = OFB_Enc_Dec(DEMO_KEY, iv_reuse, m2)
        
        return jsonify({
            "iv": iv_reuse.hex(),
            "cbc": { "c1": c1.hex(), "c2": c2.hex() },
            "ofb": { "c1": ofb_c1.hex(), "c2": ofb_c2.hex(), "recovered_xor": xor_bytes(ofb_c1, ofb_c2).hex() }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def xor_bytes(a, b):
    len_a, len_b = len(a), len(b)
    if len_a > len_b: b = b + b'\0' * (len_a - len_b)
    elif len_b > len_a: a = a + b'\0' * (len_b - len_a)
    return bytes(x ^ y for x, y in zip(a, b))