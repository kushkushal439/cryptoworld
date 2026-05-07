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
from dlp_api import dlp_api
from rsa_api import rsa_api
from pa19_api import pa19_api
from pa2_api import pa2_api
from pa1_api import pa1_api
from pa3_api import pa3_api
from pa15_api import pa15_api
from pa16_api import pa16_api
from pa17_api import pa17_api
from pa5_api import pa5_api

app.register_blueprint(md_api, url_prefix="/api/md")
app.register_blueprint(dlp_api, url_prefix="/api/dlp")
app.register_blueprint(rsa_api, url_prefix="/api/rsa")
app.register_blueprint(pa19_api, url_prefix="/api/pa19")
app.register_blueprint(pa2_api, url_prefix="/api/pa2")
app.register_blueprint(pa1_api, url_prefix="/api/pa1")
app.register_blueprint(pa3_api, url_prefix="/api/pa3")
app.register_blueprint(pa5_api, url_prefix="/api/pa5")
app.register_blueprint(pa15_api, url_prefix="/api/pa15")
app.register_blueprint(pa16_api, url_prefix="/api/pa16")
app.register_blueprint(pa17_api, url_prefix="/api/pa17")

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

def parse_ui_input(input_str, req_size, is_query=False, target_enum=None):
    """Parses hex or utf-8 string, and securely pads it by repeating."""
    if not input_str:
        return b'\x01' * req_size
        
    clean_str = input_str.replace('...', '').replace(' ', '').replace('0x', '')
    try:
        # If variable length query, treat numbers as string so 0011 != 00111
        if is_query and target_enum in (Primitive.MAC, Primitive.CRHF, Primitive.HMAC, Primitive.PRP, Primitive.PRF):
            raise ValueError()
            
        if len(clean_str) % 2 != 0:
            clean_str = '0' + clean_str
        base_bytes = bytes.fromhex(clean_str)
    except ValueError:
        # Fallback: treat it as a normal text string
        base_bytes = input_str.encode('utf-8')
        
    if is_query and target_enum in (Primitive.MAC, Primitive.CRHF, Primitive.HMAC, Primitive.PRP, Primitive.PRF):
        return base_bytes

    if len(base_bytes) < req_size:
        if is_query:
            base_bytes = base_bytes.ljust(req_size, b'\x00')
        else:
            repeats = (req_size // len(base_bytes)) + 1
            base_bytes = (base_bytes * repeats)[:req_size]
            
    return base_bytes[:req_size]

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

    source_enum = str_to_enum(source_str)
    target_enum = str_to_enum(target_str)

    # 2. Parse and pad inputs using the req_size
    input_a_bytes = parse_ui_input(input_a_str, req_size, is_query=True, target_enum=target_enum)
    input_b_bytes = parse_ui_input(input_b_str, req_size, is_query=True, target_enum=target_enum)


    try:
        source_inst, build_trace = router.reduce_with_trace(
            foundation_enum, source_enum, base_instance, input_a_bytes, key_size=req_size
        )

        target_inst, reduce_trace = router.reduce_with_trace(
            source_enum, target_enum, source_inst, input_b_bytes, key_size=req_size
        )

        # KEEP the full chain for the bottom text summary
        full_chain = [t['func'] for t in build_trace[:-1]] + [t['func'] for t in reduce_trace]

        # RE-EVALUATE the source block using its own input seed (input_a_bytes)
        # so the Left output is Source(Input Seed) and Right output is Target(Query).
        # This prevents the left side from incorrectly displaying the cascaded foundation trace evaluation.
        if build_trace:
            eval_a_bytes = router._evaluate_primitive(source_enum, source_inst, input_a_bytes, req_size)

            final_build_trace = [{"func": source_enum.name, "val": eval_a_bytes.hex() if isinstance(eval_a_bytes, bytes) else str(eval_a_bytes)}]
        else:
            final_build_trace = []
            
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