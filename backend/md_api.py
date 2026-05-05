from flask import Blueprint, request, jsonify
from Implementations.PA_7 import md_padding, xor_dummy_compress
import binascii

md_api = Blueprint('md_api', __name__)

@md_api.route('/pad', methods=['POST'])
def pad_message():
    data = request.json
    message_str = data.get('message', '')
    is_hex = data.get('is_hex', False)
    
    try:
        if is_hex:
            clean_str = message_str.replace(' ', '').replace('0x', '')
            if len(clean_str) % 2 != 0:
                clean_str = '0' + clean_str
            msg_bytes = bytes.fromhex(clean_str) if clean_str else b''
        else:
            msg_bytes = message_str.encode('utf-8')
            
        padded = md_padding(msg_bytes, 8)
        
        # Split into blocks of 8 bytes
        blocks = []
        for i in range(0, len(padded), 8):
            blocks.append(padded[i:i+8].hex())
            
        return jsonify({"status": "success", "blocks": blocks})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@md_api.route('/chain', methods=['POST'])
def compute_chain():
    data = request.json
    blocks_hex = data.get('blocks', [])
    iv_hex = data.get('iv', '00000000')
    
    try:
        iv = bytes.fromhex(iv_hex)
        assert len(iv) == 4, "IV must be 4 bytes"
        
        chain = []
        z = iv
        chain.append(z.hex())
        
        for b_hex in blocks_hex:
            block = bytes.fromhex(b_hex)
            assert len(block) == 8, "Each block must be 8 bytes"
            z = xor_dummy_compress(z, block)
            chain.append(z.hex())
            
        return jsonify({"status": "success", "chain": chain})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400
