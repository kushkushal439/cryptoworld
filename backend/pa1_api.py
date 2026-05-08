from flask import Blueprint, request, jsonify
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Implementations.PA_1 import dlp_owf_logic, convert_owf_to_prg, run_nist_tests
from CryptoPrimitives.OWF import OWF
import binascii

pa1_api = Blueprint('pa1_api', __name__)

owf = OWF(dlp_owf_logic)
prg = convert_owf_to_prg(owf)

def parse_ui_input(input_str, req_size=64):
    if not input_str:
        return b'\x01' * req_size
    clean_str = input_str.replace('...', '').replace(' ', '').replace('0x', '')
    try:
        if len(clean_str) % 2 != 0:
            clean_str = '0' + clean_str
        base_bytes = bytes.fromhex(clean_str)
    except ValueError:
        base_bytes = input_str.encode('utf-8')
    repeats = (req_size // len(base_bytes)) + 1
    return (base_bytes * repeats)[:req_size]

@pa1_api.route('/prg', methods=['POST'])
def generate_prg():
    data = request.json
    seed_str = data.get('seed', '')
    length = int(data.get('length', 16)) * 8 # length in bytes -> bits
    
    seed_bytes = parse_ui_input(seed_str, 64)
    
    out_bytes = prg.generate(seed_bytes, length)
    
    # We also need the bits for tests
    out_bits = []
    for b in out_bytes:
        for i in range(8):
            out_bits.append((b >> (7 - i)) & 1)
            
    out_bits = out_bits[:length]
    
    return jsonify({
        "output_hex": out_bytes.hex(),
        "bits": out_bits
    })

@pa1_api.route('/test', methods=['POST'])
def run_tests():
    data = request.json
    bits = data.get('bits', [])
    
    results = run_nist_tests(bits)
    
    ones = sum(bits)
    total = len(bits)
    ratio = (ones / total) * 100 if total > 0 else 0
    
    return jsonify({
        "results": results,
        "ratio": ratio
    })
