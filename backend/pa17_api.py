from flask import Blueprint, request, jsonify
import hashlib
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Implementations.PA_11 import generate_dh_parameters
from Implementations.PA_12 import rsa_keygen

pa17_api = Blueprint('pa17_api', __name__)

# --- ElGamal parameters (encryption) ---
_P, _Q, _G = generate_dh_parameters(64)
_X = random.randint(1, _Q - 1)
_H = pow(_G, _X, _P)

# --- RSA parameters (signing) ---
_RSA_SK, _RSA_PK = rsa_keygen(512)
_N = _RSA_PK['N']
_E = _RSA_PK['e']
_D = _RSA_SK['d']


def _parse_int(val: str) -> int:
    try:
        return int(val)
    except Exception:
        return -1


def _normalize_message(m: int) -> int:
    m = m % _P
    return m if m != 0 else 1


def _elgamal_enc(m: int):
    r = random.randint(1, _Q - 1)
    c1 = pow(_G, r, _P)
    c2 = (m * pow(_H, r, _P)) % _P
    return c1, c2


def _elgamal_dec(c1: int, c2: int):
    s = pow(c1, _X, _P)
    s_inv = pow(s, -1, _P)
    return (c2 * s_inv) % _P


def _hash_ciphertext(c1: int, c2: int) -> int:
    data = f"{c1}||{c2}".encode('utf-8')
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, 'big') % _N


def _sign(c1: int, c2: int) -> int:
    h = _hash_ciphertext(c1, c2)
    return pow(h, _D, _N)


def _verify(c1: int, c2: int, sigma: int) -> bool:
    h = _hash_ciphertext(c1, c2)
    return pow(sigma, _E, _N) == h


@pa17_api.route('/cca_encrypt', methods=['POST'])
def cca_encrypt():
    data = request.json or {}
    m_val = _parse_int(str(data.get('m', '')))
    if m_val < 0:
        return jsonify({"status": "error", "message": "Invalid integer message"}), 400

    m = _normalize_message(m_val)
    c1, c2 = _elgamal_enc(m)
    sigma = _sign(c1, c2)

    return jsonify({
        "status": "success",
        "m": str(m),
        "c1": str(c1),
        "c2": str(c2),
        "sigma": hex(sigma),
        "p": str(_P),
        "N": str(_N),
        "e": str(_E)
    })


@pa17_api.route('/cca_decrypt', methods=['POST'])
def cca_decrypt():
    data = request.json or {}
    c1 = _parse_int(str(data.get('c1', '')))
    c2 = _parse_int(str(data.get('c2', '')))
    sig_hex = str(data.get('sigma', '0'))

    if c1 < 0 or c2 < 0:
        return jsonify({"status": "error", "message": "Invalid ciphertext"}), 400

    try:
        sigma = int(sig_hex, 16)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid signature hex"}), 400

    h = _hash_ciphertext(c1, c2)
    sigma_e = pow(sigma, _E, _N)
    valid = (sigma_e == h)

    if not valid:
        return jsonify({
            "status": "success",
            "valid": False,
            "sigma_e": str(sigma_e),
            "expected": str(h),
            "m": None
        })

    m = _elgamal_dec(c1, c2)
    return jsonify({
        "status": "success",
        "valid": True,
        "sigma_e": str(sigma_e),
        "expected": str(h),
        "m": str(m)
    })


@pa17_api.route('/elgamal_encrypt', methods=['POST'])
def elgamal_encrypt():
    data = request.json or {}
    m_val = _parse_int(str(data.get('m', '')))
    if m_val < 0:
        return jsonify({"status": "error", "message": "Invalid integer message"}), 400

    m = _normalize_message(m_val)
    c1, c2 = _elgamal_enc(m)
    return jsonify({
        "status": "success",
        "m": str(m),
        "c1": str(c1),
        "c2": str(c2),
        "p": str(_P)
    })


@pa17_api.route('/elgamal_decrypt', methods=['POST'])
def elgamal_decrypt():
    data = request.json or {}
    c1 = _parse_int(str(data.get('c1', '')))
    c2 = _parse_int(str(data.get('c2', '')))

    if c1 < 0 or c2 < 0:
        return jsonify({"status": "error", "message": "Invalid ciphertext"}), 400

    m = _elgamal_dec(c1, c2)
    return jsonify({
        "status": "success",
        "m": str(m)
    })
