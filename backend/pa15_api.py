from flask import Blueprint, request, jsonify
import hashlib
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Implementations.PA_12 import rsa_keygen

pa15_api = Blueprint('pa15_api', __name__)

# Fixed keypair for demo speed
_SK, _PK = rsa_keygen(512)
_N = _PK['N']
_E = _PK['e']
_D = _SK['d']


def _hash_to_int(message: bytes) -> int:
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, 'big') % _N


def _parse_int(val: str) -> int:
    try:
        return int(val)
    except Exception:
        return -1


@pa15_api.route('/sign', methods=['POST'])
def sign():
    data = request.json or {}
    raw_mode = bool(data.get('raw', False))

    if raw_mode:
        m_int = _parse_int(str(data.get('m_int', '')))
        if m_int < 0:
            return jsonify({"status": "error", "message": "Invalid integer message"}), 400
        m_int = m_int % _N
        sigma = pow(m_int, _D, _N)
        return jsonify({
            "status": "success",
            "raw": True,
            "m_int": str(m_int),
            "signature": hex(sigma),
            "N": str(_N),
            "e": str(_E)
        })

    message = str(data.get('message', '')).encode('utf-8')
    h_int = _hash_to_int(message)
    sigma = pow(h_int, _D, _N)
    return jsonify({
        "status": "success",
        "raw": False,
        "hash_int": str(h_int),
        "signature": hex(sigma),
        "N": str(_N),
        "e": str(_E)
    })


@pa15_api.route('/verify', methods=['POST'])
def verify():
    data = request.json or {}
    raw_mode = bool(data.get('raw', False))
    sig_hex = str(data.get('signature', '0'))

    try:
        sigma = int(sig_hex, 16)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid signature hex"}), 400

    sigma_e = pow(sigma, _E, _N)

    if raw_mode:
        m_int = _parse_int(str(data.get('m_int', '')))
        if m_int < 0:
            return jsonify({"status": "error", "message": "Invalid integer message"}), 400
        m_int = m_int % _N
        valid = (sigma_e == m_int)
        return jsonify({
            "status": "success",
            "raw": True,
            "expected": str(m_int),
            "sigma_e": str(sigma_e),
            "valid": valid
        })

    message = str(data.get('message', '')).encode('utf-8')
    h_int = _hash_to_int(message)
    valid = (sigma_e == h_int)
    return jsonify({
        "status": "success",
        "raw": False,
        "expected": str(h_int),
        "sigma_e": str(sigma_e),
        "valid": valid
    })


@pa15_api.route('/raw-forge', methods=['POST'])
def raw_forge():
    data = request.json or {}
    m1 = _parse_int(str(data.get('m1', '')))
    m2 = _parse_int(str(data.get('m2', '')))

    if m1 < 0 or m2 < 0:
        return jsonify({"status": "error", "message": "Invalid integer messages"}), 400

    m1 = m1 % _N
    m2 = m2 % _N

    s1 = pow(m1, _D, _N)
    s2 = pow(m2, _D, _N)

    m3 = (m1 * m2) % _N
    s3 = (s1 * s2) % _N

    valid = (pow(s3, _E, _N) == m3)

    return jsonify({
        "status": "success",
        "m1": str(m1),
        "m2": str(m2),
        "s1": hex(s1),
        "s2": hex(s2),
        "m3": str(m3),
        "s3": hex(s3),
        "valid": valid,
        "N": str(_N),
        "e": str(_E)
    })
