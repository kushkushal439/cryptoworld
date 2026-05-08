# backend/pa12_api.py
from flask import Blueprint, request, jsonify
import sys
import os

# Add the parent directory to the path to allow imports from Implementations
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Implementations.PA_12 import rsa_keygen, rsa_enc, pkcs15_enc

pa12_api = Blueprint('pa12_api', __name__)

# Generate a single 512-bit key pair when the server starts.
# This will be shared for all demo requests to ensure consistency.
SK, PK = rsa_keygen(512)
KEY_SIZE_BYTES = (PK['N'].bit_length() + 7) // 8

@pa12_api.route('/get-key-details', methods=['GET'])
def get_key_details():
    """Endpoint to provide the public key details to the frontend."""
    return jsonify({
        'N': hex(PK['N']),
        'e': PK['e'],
        'bits': PK['N'].bit_length()
    })

@pa12_api.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    message_str = data.get('message', '')
    mode = data.get('mode', 'textbook') # 'textbook' or 'pkcs15'
    
    if not message_str:
        return jsonify({"error": "Message cannot be empty"}), 400

    message_bytes = message_str.encode('utf-8')

    if mode == 'textbook':
        # Textbook RSA is deterministic
        m_int = int.from_bytes(message_bytes, 'big')
        if m_int >= PK['N']:
            return jsonify({"error": "Message is too large for this RSA key"}), 400
        
        c1 = rsa_enc(PK, m_int)
        c2 = rsa_enc(PK, m_int)
        
        return jsonify({
            'c1': hex(c1),
            'c2': hex(c2),
            'padding1': None,
            'padding2': None
        })

    elif mode == 'pkcs15':
        # PKCS#1 v1.5 is randomized
        
        # We need to extract the padding for the demo, which the original function doesn't return.
        # So, we'll replicate the padding logic here to capture it.
        def generate_padded_message(m):
            if len(m) > KEY_SIZE_BYTES - 11:
                raise ValueError("Message too long")
            
            ps_len = KEY_SIZE_BYTES - 3 - len(m)
            ps = bytearray()
            while len(ps) < ps_len:
                rand_byte = os.urandom(1)
                if rand_byte != b'\x00':
                    ps.extend(rand_byte)
            
            em = b'\x00\x02' + bytes(ps) + b'\x00' + m
            return em, bytes(ps)

        try:
            em1, ps1 = generate_padded_message(message_bytes)
            em2, ps2 = generate_padded_message(message_bytes)

            c1 = rsa_enc(PK, int.from_bytes(em1, 'big'))
            c2 = rsa_enc(PK, int.from_bytes(em2, 'big'))

            return jsonify({
                'c1': hex(c1),
                'c2': hex(c2),
                'padding1': ps1.hex(),
                'padding2': ps2.hex()
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    else:
        return jsonify({"error": "Invalid encryption mode specified"}), 400
