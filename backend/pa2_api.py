from flask import Blueprint, request, jsonify
from CryptoPrimitives.AES import aes_prf
import binascii

pa2_api = Blueprint('pa2_api', __name__)

def parse_hex_key(hex_str, default_bytes=16):
    try:
        clean_str = hex_str.replace(' ', '').replace('0x', '')
        if len(clean_str) % 2 != 0:
            clean_str = '0' + clean_str
        res = binascii.unhexlify(clean_str)
        if len(res) < default_bytes:
            res = res + b'\x00' * (default_bytes - len(res))
        return res[:default_bytes]
    except:
        return b'\x00' * default_bytes

def fake_prg(seed_bytes):
    # Uses aes_prf to double length: F_s(0) || F_s(1)
    q0 = b'\x00' * 16
    q1 = b'\xff' * 16
    out0 = aes_prf.evaluate(seed_bytes, q0)
    out1 = aes_prf.evaluate(seed_bytes, q1)
    return out0, out1

@pa2_api.route('/ggm_tree', methods=['POST'])
def ggm_tree():
    data = request.json
    key_hex = data.get('key', '00' * 16)
    query_str = data.get('query', '0000') # default 4 bits
    
    # We cap depth at 8 (256 leaves min)
    depth = len(query_str)
    if depth > 8:
        depth = 8
        query_str = query_str[:8]
        
    key_bytes = parse_hex_key(key_hex, 16)
    
    # Build tree and return list of nodes
    # node: { id: "010", value: "abcdef...", active: true, children: ["0100", "0101"] } # though we can just infer connections
    
    # Breadth-first generation
    # queue of (id, seed_bytes)
    nodes = []
    
    current_level = [("", key_bytes)]
    
    for level in range(depth + 1):
        next_level = []
        for path, seed in current_level:
            is_active = (path == query_str[:len(path)])
            nodes.append({
                "id": path,
                "value": binascii.hexlify(seed).decode('utf-8'),
                "active": is_active,
                "is_leaf": (level == depth)
            })
            if level < depth:
                out0, out1 = fake_prg(seed)
                next_level.append((path + "0", out0))
                next_level.append((path + "1", out1))
        current_level = next_level
        
    # Find the leaf value for the full query
    leaf_val = ""
    for n in nodes:
        if n["id"] == query_str:
            leaf_val = n["value"]
            break

    return jsonify({
        "status": "success",
        "nodes": nodes,
        "leaf_value": leaf_val,
        "query": query_str,
        "depth": depth
    })
