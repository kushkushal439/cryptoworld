from flask import Blueprint, request, jsonify
import os
import random
import uuid
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Implementations.PA_3 import Enc, Enc_broken

pa3_api = Blueprint('pa3_api', __name__)

# In-memory challenge store (challenge_id -> b)
_challenges = {}

# Fixed nonce reused across rounds when reuse_nonce is enabled
_FIXED_R = os.urandom(16)


def _to_bytes(message: str) -> bytes:
    return message.encode('utf-8')


@pa3_api.route('/challenge', methods=['POST'])
def challenge():
    data = request.json or {}
    m0 = data.get('m0', '')
    m1 = data.get('m1', '')
    reuse_nonce = bool(data.get('reuse_nonce', False))

    if len(m0) != len(m1):
        return jsonify({
            "status": "error",
            "message": "m0 and m1 must be equal length"
        }), 400

    key = os.urandom(16)
    b = random.choice([0, 1])
    mb = m0 if b == 0 else m1

    if reuse_nonce:
        r, c = Enc_broken(key, _to_bytes(mb), _FIXED_R)
        r0, c0 = Enc_broken(key, _to_bytes(m0), _FIXED_R)
    else:
        r, c = Enc(key, _to_bytes(mb))
        r0, c0 = None, None

    challenge_id = uuid.uuid4().hex
    _challenges[challenge_id] = b

    response = {
        "status": "success",
        "challenge_id": challenge_id,
        "ciphertext": {
            "r": r.hex(),
            "c": c.hex()
        },
        "reuse_nonce": reuse_nonce
    }

    if reuse_nonce:
        response["oracle"] = {
            "r": r0.hex(),
            "c": c0.hex()
        }

    return jsonify(response)


@pa3_api.route('/guess', methods=['POST'])
def guess():
    data = request.json or {}
    challenge_id = data.get('challenge_id')
    guess_b = int(data.get('guess', -1))

    if challenge_id not in _challenges:
        return jsonify({
            "status": "error",
            "message": "Unknown or expired challenge id"
        }), 400

    actual_b = _challenges.pop(challenge_id)
    correct = (guess_b == actual_b)

    return jsonify({
        "status": "success",
        "correct": correct,
        "actual_b": actual_b
    })
