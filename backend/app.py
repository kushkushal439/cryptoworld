from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Primitive_enums import Primitive
from God import God

from CryptoPrimitives.OWF import OWF
from Implementations.PA_1 import dlp_owf_logic

app = Flask(__name__)
CORS(app)
from md_api import md_api
app.register_blueprint(md_api, url_prefix="/api/md")

router = God()

def str_to_enum(name_str):
    mapping = {
        "OWF": Primitive.OWF, "PRG": Primitive.PRG, "PRF": Primitive.PRF,
        "OWP": Primitive.OWP, "PRP": Primitive.PRP, "MAC": Primitive.MAC,
        "CRHF": Primitive.CRHF, "HMAC": Primitive.HMAC
    }
    for k, v in mapping.items():
        if name_str and name_str.startswith(k):
            return v
    return None

def parse_hex_input(hex_str, default_bytes=16):
    """Robustly parses whatever the user types in the UI into bytes."""
    try:
        clean_str = hex_str.replace('...', '').replace(' ', '').replace('0x', '')
        # Pad with a leading zero if the user types an odd number of characters
        if len(clean_str) % 2 != 0:
            clean_str = '0' + clean_str
        if not clean_str:
            return os.urandom(default_bytes)
        return bytes.fromhex(clean_str)
    except:
        return os.urandom(default_bytes)
# backend/app.py

def parse_ui_input(input_str, req_size):
    """Parses hex or utf-8 string, and securely pads it by repeating."""
    if not input_str:
        return b'\x01' * req_size
        
    clean_str = input_str.replace('...', '').replace(' ', '').replace('0x', '')
    try:
        if len(clean_str) % 2 != 0:
            clean_str = '0' + clean_str
        base_bytes = bytes.fromhex(clean_str)
    except ValueError:
        # Fallback: treat it as a normal text string (like "hii")
        base_bytes = input_str.encode('utf-8')
        
    # Repeat the bytes to fill the size (e.g., "hii" -> "hiihiihii...")
    # This guarantees the 'r' half of the DLP seed is never all zeros!
    repeats = (req_size // len(base_bytes)) + 1
    return (base_bytes * repeats)[:req_size]

@app.route('/api/reduce', methods=['POST'])
def reduce():
    data = request.json
    foundation_str = data.get('foundation', '')
    source_str = data.get('source', '')
    target_str = data.get('target', '')
    
    input_a_str = data.get('input', '')  
    input_b_str = data.get('query', '')  
    
    # 1. Determine Foundation & Required Key Size
    if "AES" in foundation_str:
        from CryptoPrimitives.AES import aes_prf
        foundation_enum = Primitive.PRP
        base_instance = aes_prf
        req_size = 16
    else:
        foundation_enum = Primitive.OWP
        from Implementations.PA_1 import dlp_owf_logic
        base_instance = OWF(dlp_owf_logic)
        req_size = 64  # DLP GL-construction requires 64 bytes

    # 2. Parse and pad inputs using the req_size
    input_a_bytes = parse_ui_input(input_a_str, req_size)
    input_b_bytes = parse_ui_input(input_b_str, req_size)

    source_enum = str_to_enum(source_str)
    target_enum = str_to_enum(target_str)

    try:
        source_inst, build_trace = router.reduce_with_trace(
            foundation_enum, source_enum, base_instance, input_a_bytes, key_size=req_size
        )

        target_inst, reduce_trace = router.reduce_with_trace(
            source_enum, target_enum, source_inst, input_b_bytes, key_size=req_size
        )

        # KEEP the full chain for the bottom text summary
        full_chain = [t['func'] for t in build_trace[:-1]] + [t['func'] for t in reduce_trace]

        # FILTER the traces to only include the final output step
        final_build_trace = [build_trace[-1]] if build_trace else []
        final_reduce_trace = [reduce_trace[-1]] if reduce_trace else []

        return jsonify({
            "status": "success",
            "build_trace": final_build_trace,
            "reduce_trace": final_reduce_trace,
            "full_chain": full_chain,
            "message": "Reduction executed successfully."
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)