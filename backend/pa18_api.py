# backend/pa18_api.py
from flask import Blueprint, request, jsonify
import sys
import os
import random

# Add the parent directory to the path to allow imports from Implementations
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Implementations.PA_18 import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2, pkcs15_dec

pa18_api = Blueprint('pa18_api', __name__)

# In a real application, state would be stored in a session or a database.
# For this demo, we'll use a simple global dictionary to hold state between steps.
# This is not thread-safe but is sufficient for a single-user demo.
demo_state = {}

@pa18_api.route('/receiver-step1', methods=['POST'])
def receiver_step1():
    """
    Bob (the user) initiates the protocol by choosing a bit 'b'.
    The backend runs Receiver Step 1, stores the secret key, and returns the public keys.
    """
    data = request.get_json()
    b = data.get('b')
    if b not in [0, 1]:
        return jsonify({"error": "Choice bit 'b' must be 0 or 1"}), 400

    # These are Alice's secret messages, hardcoded for the demo
    m0 = b"The nuclear launch code is: 1234"
    m1 = b"The secret recipe is: 1 cup sugar"
    
    # Run Receiver Step 1 from PA_18
    pk0, pk1, sk_b = OT_Receiver_Step1(b, bits=512) # Using 512 bits for speed

    # Store the state for the next step
    demo_state['sk_b'] = sk_b
    demo_state['b'] = b
    demo_state['m0'] = m0
    demo_state['m1'] = m1
    demo_state['pk0'] = pk0
    demo_state['pk1'] = pk1

    return jsonify({
        "message": "Receiver generated two public keys.",
        "pk0_N": hex(pk0['N']),
        "pk1_N": hex(pk1['N']),
    })

@pa18_api.route('/sender-step', methods=['GET'])
def sender_step():
    """
    Alice (the backend) receives the public keys and encrypts her messages.
    """
    if 'pk0' not in demo_state or 'm0' not in demo_state:
        return jsonify({"error": "Protocol not initiated. Please run Step 1 first."}), 400

    pk0 = demo_state['pk0']
    pk1 = demo_state['pk1']
    m0 = demo_state['m0']
    m1 = demo_state['m1']

    # Run Sender Step from PA_18
    c0, c1 = OT_Sender_Step(pk0, pk1, m0, m1)

    # Store the ciphertexts for the final step
    demo_state['c0'] = c0
    demo_state['c1'] = c1

    return jsonify({
        "message": "Sender encrypted both messages with the respective public keys.",
        "c0": hex(c0),
        "c1": hex(c1),
    })

@pa18_api.route('/receiver-step2', methods=['GET'])
def receiver_step2():
    """
    Bob (the user) receives the ciphertexts and decrypts his chosen one.
    """
    if 'sk_b' not in demo_state or 'c0' not in demo_state:
        return jsonify({"error": "Protocol not run correctly. Please start over."}), 400

    sk_b = demo_state['sk_b']
    c0 = demo_state['c0']
    c1 = demo_state['c1']
    b = demo_state['b']

    # Run Receiver Step 2 from PA_18
    recovered_message_bytes = OT_Receiver_Step2(sk_b, c0, c1, b)
    
    if recovered_message_bytes is None:
        return jsonify({"error": "Decryption failed. Padding was invalid."}), 500

    return jsonify({
        "message": f"Receiver decrypted C{b} using the stored secret key.",
        "recovered_message": recovered_message_bytes.decode('utf-8', 'replace')
    })

@pa18_api.route('/cheat-attempt', methods=['GET'])
def cheat_attempt():
    """
    Bob (the user) tries to decrypt the other ciphertext. This should fail.
    """
    if 'sk_b' not in demo_state or 'c0' not in demo_state:
        return jsonify({"error": "Protocol not run correctly. Please start over."}), 400

    sk_b = demo_state['sk_b']
    c0 = demo_state['c0']
    c1 = demo_state['c1']
    b = demo_state['b']
    
    # The ciphertext to cheat with is the one Bob did NOT choose
    c_unchosen = c1 if b == 0 else c0
    
    # Attempt to decrypt using the wrong key. This relies on pkcs15_dec returning None.
    # The state `sk_b` holds the secret key for index `b`.
    decryption_result = pkcs15_dec(sk_b, c_unchosen)

    if decryption_result is None:
        return jsonify({
            "message": f"Cheat attempt failed as expected. Decrypting C{1-b} with SK{b} resulted in a padding error.",
            "success": True
        })
    else:
        return jsonify({
            "message": "Cheat attempt unexpectedly succeeded. This should not happen.",
            "success": False,
            "leaked_message": decryption_result.decode('utf-8', 'replace')
        })
