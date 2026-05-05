from flask import Blueprint, request, jsonify
from Implementations.PA_18 import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2
import binascii

pa19_api = Blueprint('pa19_api', __name__)

@pa19_api.route('/and', methods=['POST'])
def secure_and():
    data = request.json
    a = int(data.get('a', 0))
    b = int(data.get('b', 0))

    if a not in (0, 1) or b not in (0, 1):
        return jsonify({"status": "error", "message": "Inputs must be bits (0 or 1)"}), 400

    # We use 128 bit for speed in demo
    bits = 128
    
    # Transcript
    transcript = []
    
    # Bob (Receiver) prepares to receive based on his bit 'b'
    pk_0, pk_1, state = OT_Receiver_Step1(b=b, bits=bits)
    
    transcript.append({
        "step": "Bob runs OT receiver",
        "details": f"Bob generates two public keys pk_0 and pk_1, but only keeps the secret key for choice b={b}."
    })
    transcript.append({
        "step": "Bob -> Alice",
        "details": f"Bob sends pk_0={str(pk_0.get('N', ''))[:10]}... and pk_1={str(pk_1.get('N', ''))[:10]}... to Alice." 
    })

    # Alice (Sender) prepares her two messages: m0 = 0, m1 = a
    m_0 = (0).to_bytes(1, 'big')
    m_1 = a.to_bytes(1, 'big')
    
    transcript.append({
        "step": "Alice sets up OT messages",
        "details": f"Alice prepares messages m_0=0 and m_1={a} based on her bit a={a}."
    })

    # Alice encrypts and sends
    c_0, c_1 = OT_Sender_Step(pk_0, pk_1, m_0, m_1)
    
    transcript.append({
        "step": "Alice -> Bob",
        "details": f"Alice encrypts m_0 under pk_0 to get c_0, and m_1 under pk_1 to get c_1. She sends c_0={hex(c_0)[:10]}... and c_1={hex(c_1)[:10]}... to Bob."
    })

    # Bob decrypts
    recovered_bytes = OT_Receiver_Step2(state, c_0, c_1, b)
    result = int.from_bytes(recovered_bytes, 'big')

    transcript.append({
        "step": "Bob receives m_b",
        "details": f"Bob decrypts c_{b} using his private key and receives m_{b} = {result}, which is equal to {a} AND {b}."
    })

    return jsonify({
        "status": "success",
        "a": a,
        "b": b,
        "result": result,
        "transcript": transcript
    })
