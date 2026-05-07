from flask import Blueprint, request, jsonify
import os
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Implementations.PA_11 import generate_dh_parameters

pa16_api = Blueprint('pa16_api', __name__)

# Generate a moderately small group for fast demos
_P, _Q, _G = generate_dh_parameters(64)
_X = random.randint(1, _Q - 1)
_H = pow(_G, _X, _P)


def _normalize_message(m: int) -> int:
    m = m % _P
    return m if m != 0 else 1


def _parse_int(val: str) -> int:
    try:
        return int(val)
    except Exception:
        return -1


def _enc(m: int):
    r = random.randint(1, _Q - 1)
    c1 = pow(_G, r, _P)
    c2 = (m * pow(_H, r, _P)) % _P
    return c1, c2


def _dec(c1: int, c2: int):
    s = pow(c1, _X, _P)
    s_inv = pow(s, -1, _P)
    return (c2 * s_inv) % _P


@pa16_api.route('/params', methods=['GET'])
def params():
    return jsonify({
        "status": "success",
        "p": str(_P),
        "g": str(_G),
        "h": str(_H)
    })


@pa16_api.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json or {}
    m_val = _parse_int(str(data.get('m', '')))
    if m_val < 0:
        return jsonify({"status": "error", "message": "Invalid integer message"}), 400

    m = _normalize_message(m_val)
    c1, c2 = _enc(m)

    return jsonify({
        "status": "success",
        "m": str(m),
        "c1": str(c1),
        "c2": str(c2),
        "p": str(_P)
    })


@pa16_api.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json or {}
    c1 = _parse_int(str(data.get('c1', '')))
    c2 = _parse_int(str(data.get('c2', '')))

    if c1 < 0 or c2 < 0:
        return jsonify({"status": "error", "message": "Invalid ciphertext"}), 400

    m = _dec(c1, c2)
    return jsonify({
        "status": "success",
        "m": str(m)
    })


@pa16_api.route('/malleate', methods=['POST'])
def malleate():
    data = request.json or {}
    c1 = _parse_int(str(data.get('c1', '')))
    c2 = _parse_int(str(data.get('c2', '')))
    multiplier = _parse_int(str(data.get('multiplier', '2')))

    if c1 < 0 or c2 < 0 or multiplier < 0:
        return jsonify({"status": "error", "message": "Invalid ciphertext or multiplier"}), 400

    new_c2 = (multiplier * c2) % _P
    m_new = _dec(c1, new_c2)

    return jsonify({
        "status": "success",
        "c1": str(c1),
        "c2": str(new_c2),
        "m": str(m_new)
    })
