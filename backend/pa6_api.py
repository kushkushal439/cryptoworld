# backend/pa6_api.py
from flask import Blueprint, request, jsonify
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from Implementations.PA_6 import setup_primitive_instances, CCA_Challenger
    cpa_server, mac_instance = setup_primitive_instances()
    challenger = CCA_Challenger(cpa_server, mac_instance)
except Exception as e:
    print(f"Error loading PA_6 implementations: {e}")
    challenger = None

pa6_api = Blueprint('pa6_api', __name__)

@pa6_api.route('/encrypt', methods=['POST'])
def encrypt_message():
    if not challenger:
        return jsonify({"error": "PA6 Not properly initialized"}), 500

    data = request.json
    m_str = data.get('message', "SEND_100_DOLLARS")
    m_bytes = m_str.encode('utf-8')
    
    try:
        c, t = challenger.cca_scheme.CCA_Enc(challenger.k_E, challenger.k_M, m_bytes)
        r, c_E = c
        
        return jsonify({
            'message': m_str,
            'r': r.hex(),
            'c_E': c_E.hex(),
            't': t.hex()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@pa6_api.route('/decrypt', methods=['POST'])
def decrypt_message():
    if not challenger:
        return jsonify({"error": "PA6 Not properly initialized"}), 500

    data = request.json
    try:
        r = bytes.fromhex(data.get('r', ''))
        c_E = bytes.fromhex(data.get('c_E', ''))
        t = bytes.fromhex(data.get('t', ''))
    except Exception as e:
        return jsonify({"error": "Invalid hex encoding"}), 400

    # CPA Decryption (ignores MAC and decrypts blindly)
    try:
        m_cpa_bytes = challenger.cca_scheme.cpa.decrypt(challenger.k_E, r, c_E)
        try:
            m_cpa = m_cpa_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # Printable display for garbled output
            m_cpa = "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in m_cpa_bytes)
    except Exception as e:
        m_cpa = f"Error: {str(e)}"
        
    # CCA Decryption (MAC is verified first)
    try:
        m_cca_bytes = challenger.cca_scheme.CCA_Dec(challenger.k_E, challenger.k_M, (r, c_E), t)
        if m_cca_bytes is None:
            m_cca = "⊥ (MAC Verification Failed)"
        else:
            try:
                m_cca = m_cca_bytes.decode('utf-8')
            except UnicodeDecodeError:
                m_cca = "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in m_cca_bytes)
    except Exception:
        m_cca = "⊥ (MAC Verification Failed)"

    return jsonify({
        'cpa_result': m_cpa,
        'cca_result': m_cca
    })
