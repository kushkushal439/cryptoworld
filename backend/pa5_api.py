from flask import Blueprint, request, jsonify
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from CryptoPrimitives.AES import aes_prf
from CryptoPrimitives.MAC import MAC
from Implementations.PA_8 import DLP_Hash, generate_safe_prime
from Implementations.PA_7 import md_padding
import random
import struct

# Generate a small hash instance for the API
_p, _q = generate_safe_prime(64)
_g = pow(random.randint(2, _p-2), 2, _p)
_h_hat = pow(_g, random.randint(1, _q-1), _p)
_block_size = (_q.bit_length() + 7) // 8
_hash_instance = DLP_Hash(_p, _q, _g, _h_hat, block_size=_block_size)
_hmac_mac = MAC(_hash_instance, mode="HMAC")


pa5_api = Blueprint('pa5_api', __name__)

# -----------------------------------------------------------------------
# Shared MAC instances (CBC and PRF modes)
# -----------------------------------------------------------------------

_cbc_mac = MAC(aes_prf, mode="CBC")
_prf_mac = MAC(aes_prf, mode="PRF")

# Secret key – regenerated per process, persists for the session
_SECRET_KEY = os.urandom(16)

# In-memory store of (message -> tag) pairs shown to the adversary
_oracle_history: dict[str, str] = {}


def _msg_to_bytes(msg: str) -> bytes:
    """Convert a hex-or-text message string to bytes."""
    try:
        cleaned = msg.replace(' ', '').replace('0x', '')
        if len(cleaned) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in cleaned) and len(cleaned) >= 2:
            return bytes.fromhex(cleaned)
    except Exception:
        pass
    return msg.encode('utf-8')


# -----------------------------------------------------------------------
# Route 1 – query the signing oracle
# -----------------------------------------------------------------------

@pa5_api.route('/oracle', methods=['POST'])
def oracle():
    """
    Adversary queries the MAC oracle.
    Returns a tag for the requested message (always CBC-MAC mode).
    Adds the pair to the oracle history.
    """
    data = request.json or {}
    message = str(data.get('message', ''))

    if not message:
        return jsonify({"status": "error", "message": "Message is required"}), 400

    msg_bytes = _msg_to_bytes(message)
    tag = _cbc_mac.tag(_SECRET_KEY, msg_bytes)
    tag_hex = tag.hex()

    _oracle_history[message] = tag_hex

    return jsonify({
        "status": "success",
        "message": message,
        "tag": tag_hex,
        "history_count": len(_oracle_history)
    })


# -----------------------------------------------------------------------
# Route 2 – attempt a forgery
# -----------------------------------------------------------------------

@pa5_api.route('/forge', methods=['POST'])
def forge():
    """
    Adversary submits (m*, t*) for a message NOT in the oracle history.
    Returns whether the forgery was accepted or rejected.
    """
    data = request.json or {}
    message = str(data.get('message', ''))
    tag_hex = str(data.get('tag', ''))

    if not message or not tag_hex:
        return jsonify({"status": "error", "message": "message and tag are required"}), 400

    if message in _oracle_history:
        return jsonify({
            "status": "error",
            "message": "Message was already signed by the oracle – choose a new message!"
        }), 400

    try:
        tag_bytes = bytes.fromhex(tag_hex.replace('0x', '').replace(' ', ''))
    except Exception:
        return jsonify({"status": "error", "message": "Invalid tag hex encoding"}), 400

    msg_bytes = _msg_to_bytes(message)
    accepted = _cbc_mac.vrfy(_SECRET_KEY, msg_bytes, tag_bytes)

    return jsonify({
        "status": "success",
        "accepted": accepted,
        "message": message,
        "tag_submitted": tag_hex,
        "correct_tag": _cbc_mac.tag(_SECRET_KEY, msg_bytes).hex() if not accepted else tag_hex
    })


# -----------------------------------------------------------------------
# Route 3 – reset the oracle history
# -----------------------------------------------------------------------

@pa5_api.route('/reset', methods=['POST'])
def reset():
    """Reset oracle history and optionally rotate the secret key."""
    global _SECRET_KEY, _oracle_history
    _oracle_history = {}
    _SECRET_KEY = os.urandom(16)
    return jsonify({"status": "success", "message": "Oracle history cleared and key rotated."})


# -----------------------------------------------------------------------
# Route 4 – get current oracle history (for display)
# -----------------------------------------------------------------------

@pa5_api.route('/history', methods=['GET'])
def history():
    return jsonify({
        "status": "success",
        "history": [{"message": m, "tag": t} for m, t in _oracle_history.items()]
    })


# -----------------------------------------------------------------------
# Route 5 – length-extension attack demo on naive H(k||m)
# -----------------------------------------------------------------------

@pa5_api.route('/length-extension', methods=['POST'])
def length_extension():
    """
    Demonstrates the length-extension attack on a naive CBC-MAC used as
    H(k || m).

    Given (m, t) where t = CBC_MAC(k, m), the adversary appends a suffix m'
    and produces a valid tag for (m || pad || m') without knowing k.

    How:
      The CBC-MAC state after processing m is exactly t.
      Re-initialising the CBC-MAC with IV = t and feeding m' through
      yields a valid tag for the extended message.
    """
    data = request.json or {}
    original_message = str(data.get('message', 'data=100'))
    suffix = str(data.get('suffix', '&admin=1'))

    if not suffix:
        return jsonify({"status": "error", "message": "suffix is required"}), 400

    orig_bytes = _msg_to_bytes(original_message)
    suffix_bytes = _msg_to_bytes(suffix)

    # --- Honest sender (Naive H(k||m)) ---
    naive_payload = _SECRET_KEY + orig_bytes
    honest_tag = _hash_instance.hash(naive_payload)

    # --- Length-extension attack ---
    # The padding MD-strengthening adds
    original_padded = md_padding(naive_payload, _hash_instance.block_size)
    padding_bytes = original_padded[len(naive_payload):]
    
    # Extended message that the server would verify
    extended_message_bytes = orig_bytes + padding_bytes + suffix_bytes

    # Forge: use the honest tag as the new IV for the suffix
    # 1. Adversary computes padding for the NEW total length, guessing len(k)
    total_len_bits = (len(original_padded) + len(suffix_bytes)) * 8
    
    suffix_padded_array = bytearray(suffix_bytes)
    suffix_padded_array.append(0x80)
    # We want (len(original_padded) + len(suffix_padded_array) + 8) % block_size == 0
    while (len(original_padded) + len(suffix_padded_array) + 8) % _hash_instance.block_size != 0:
        suffix_padded_array.append(0x00)
    suffix_padded_array.extend(struct.pack('>Q', total_len_bits))
    padded_suffix = bytes(suffix_padded_array)

    # Process suffix blocks using the honest_tag as the initial chaining value
    forged_state = honest_tag
    for i in range(0, len(padded_suffix), _hash_instance.block_size):
        block = padded_suffix[i:i + _hash_instance.block_size]
        forged_state = _hash_instance._dlp_compress(forged_state, block)

    forged_tag = forged_state

    # --- Verify the forged tag against the extended message ---
    server_tag = _hash_instance.hash(_SECRET_KEY + extended_message_bytes)
    attack_success = (forged_tag == server_tag)

    # --- HMAC is NOT vulnerable ---
    # We use our newly supported HMAC mode
    hmac_honest_tag = _hmac_mac.tag(_SECRET_KEY, orig_bytes)
    hmac_server_tag = _hmac_mac.tag(_SECRET_KEY, extended_message_bytes)
    
    # Adversary tries the same trick on HMAC
    hmac_forged_state = hmac_honest_tag
    for i in range(0, len(padded_suffix), _hash_instance.block_size):
        block = padded_suffix[i:i + _hash_instance.block_size]
        hmac_forged_state = _hash_instance._dlp_compress(hmac_forged_state, block)
        
    hmac_vulnerable = (hmac_forged_state == hmac_server_tag)

    return jsonify({
        "status": "success",
        "original_message": original_message,
        "original_tag": honest_tag.hex(),
        "suffix": suffix,
        "padding_bytes": padding_bytes.hex(),
        "extended_message_hex": extended_message_bytes.hex(),
        "forged_tag": forged_tag.hex(),
        "server_tag": server_tag.hex(),
        "attack_success": attack_success,
        "hmac_vulnerable": hmac_vulnerable,
        "explanation": (
            "The adversary used t = H(k||m) as the new initial chaining value "
            "and processed the suffix without knowing k. The server computes the same "
            "value when it verifies the extended message."
            if attack_success else
            "Attack failed (unexpected – check implementation)."
        )
    })


# -----------------------------------------------------------------------
# Route 6 – PRF-MAC vs CBC-MAC comparison (fixed-length vs variable)
# -----------------------------------------------------------------------

@pa5_api.route('/compare', methods=['POST'])
def compare():
    """
    Demonstrates PRF-MAC (fixed length) vs CBC-MAC (variable length) side-by-side.
    PRF-MAC: tag = F_k(m)  – only works for exactly one block.
    CBC-MAC: tag = chain F_k over all blocks – works for any length.
    """
    data = request.json or {}
    message = str(data.get('message', 'Hello World!'))
    key_hex = str(data.get('key', ''))

    if key_hex:
        try:
            key = bytes.fromhex(key_hex.replace(' ', ''))[:16].ljust(16, b'\x00')
        except Exception:
            key = _SECRET_KEY
    else:
        key = _SECRET_KEY

    msg_bytes = _msg_to_bytes(message)

    # PRF-MAC: pad/truncate to exactly 16 bytes
    prf_input = msg_bytes[:16].ljust(16, b'\x00')
    prf_tag = _prf_mac.tag(key, prf_input)

    # CBC-MAC: variable length
    cbc_tag = _cbc_mac.tag(key, msg_bytes)

    return jsonify({
        "status": "success",
        "message": message,
        "message_hex": msg_bytes.hex(),
        "key_hex": key.hex(),
        "prf_mac": {
            "input_hex": prf_input.hex(),
            "tag": prf_tag.hex(),
            "note": "Message padded/truncated to 16 bytes"
        },
        "cbc_mac": {
            "block_count": (len(msg_bytes) + 15) // 16,
            "tag": cbc_tag.hex(),
            "note": "Processes all blocks via chaining"
        }
    })