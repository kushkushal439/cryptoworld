from flask import Blueprint, request, jsonify
from Implementations.PA_12 import rsa_keygen, rsa_enc, pkcs15_enc
from Implementations.PA_14 import hastad_attack, crt

rsa_api = Blueprint('rsa_api', __name__)

@rsa_api.route('/hastad', methods=['POST'])
def hastad():
    data = request.json
    message_str = data.get('message', 'SECRET')
    use_pkcs = data.get('use_pkcs', False)
    
    secret_bytes = message_str.encode('utf-8')
    m = int.from_bytes(secret_bytes, 'big')
    
    e = 3
    # Use 64-bit for textbook, but bump to 256-bit for PKCS since padding requires >= 11 bytes space
    key_size = 256 if use_pkcs else 64
    keys = [rsa_keygen(key_size, fixed_e=e) for _ in range(3)]
    moduli = [pk['N'] for sk, pk in keys]
    
    if use_pkcs:
        try:
            ciphertexts = [pkcs15_enc(keys[i][1], secret_bytes) for i in range(3)]
            # Even if PKCS is used, we can still run CRT on the ciphertexts
            m_pow_e = crt(ciphertexts, moduli)
            try:
                recovered_m = hastad_attack(ciphertexts, moduli, e)
                result = "SUCCESS" if recovered_m == m else "FAIL (Attack Defeated)"
                try:
                    recovered_str = recovered_m.to_bytes((recovered_m.bit_length() + 7) // 8, 'big').decode('utf-8')
                except:
                    recovered_str = "Garbage (Could not decode to UTF-8)"
            except Exception as ex:
                recovered_m = 0
                recovered_str = "Garbage"
                result = f"FAIL (Attack Defeated: {ex})"
        except Exception as ex:
            return jsonify({"status": "error", "message": f"PKCS#1 v1.5 Encoding Failed: {ex}"})
    else:
        # Textbook RSA (Vulnerable)
        ciphertexts = [rsa_enc(keys[i][1], m) for i in range(3)]
        m_pow_e = crt(ciphertexts, moduli)
        recovered_m = hastad_attack(ciphertexts, moduli, e)
        result = "SUCCESS" if recovered_m == m else "FAIL"
        try:
            recovered_str = recovered_m.to_bytes((recovered_m.bit_length() + 7) // 8, 'big').decode('utf-8')
        except:
            recovered_str = "Garbage (Could not decode to UTF-8)"
        
    return jsonify({
        "status": "success",
        "message_int": str(m),
        "moduli": [str(n) for n in moduli],
        "ciphertexts": [str(c) for c in ciphertexts],
        "m_pow_e": str(m_pow_e),
        "recovered_m": str(recovered_m),
        "recovered_str": recovered_str,
        "result": result
    })
