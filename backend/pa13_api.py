from flask import Blueprint, request, jsonify
import sys
import os
import random
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Implementations.PA_13 import square_and_multiply

pa13_api = Blueprint('pa13_api', __name__)

def miller_rabin_trace(n: int, k: int):
    if n <= 1:
        return {"verdict": "COMPOSITE", "reason": "Base case (n <= 1)", "rounds": []}
    if n <= 3:
        return {"verdict": "PROBABLY PRIME", "reason": "Base case (n <= 3)", "rounds": []}
    if n % 2 == 0:
        return {"verdict": "COMPOSITE", "reason": "Even number", "rounds": []}

    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    rounds_trace = []
    verdict = "PROBABLY PRIME"
    reason = "Passed all k rounds"
    
    for round_idx in range(1, k + 1):
        a = random.randrange(2, n - 1)
        
        # Explicit Fermat Test for demo purposes
        fermat_val = square_and_multiply(a, n - 1, n)
        fermat_pass = (fermat_val == 1)
        
        x = square_and_multiply(a, d, n)
        
        round_info = {
            "round": round_idx,
            "a": hex(a),
            "fermat_pass": fermat_pass,
            "sequence": [hex(x)],
            "outcome": "",
            "caught_by_square_root": False
        }
        
        if x == 1 or x == n - 1:
            round_info["outcome"] = "PASS (x == 1 or x == n-1)"
            rounds_trace.append(round_info)
            continue
            
        passed_this_round = False
        for _ in range(s - 1):
            x = square_and_multiply(x, 2, n)
            round_info["sequence"].append(hex(x))
            if x == n - 1:
                passed_this_round = True
                round_info["outcome"] = "PASS (x == n-1 in squaring loop)"
                break
                
        if not passed_this_round:
            verdict = "COMPOSITE"
            round_info["outcome"] = "FAIL (No n-1 found)"
            if fermat_pass:
                round_info["caught_by_square_root"] = True
                reason = "Failed Miller-Rabin (Non-trivial square root of 1 found) despite passing Fermat!"
            else:
                reason = "Failed Miller-Rabin test."
                
            rounds_trace.append(round_info)
            break
            
        rounds_trace.append(round_info)
        
    return {
        "verdict": verdict,
        "n_hex": hex(n),
        "s": s,
        "d_hex": hex(d),
        "reason": reason,
        "rounds": rounds_trace
    }

@pa13_api.route('/test', methods=['POST'])
def test_primality():
    data = request.json or {}
    n_str = str(data.get('n', ''))
    k = int(data.get('k', 40))
    
    if not n_str:
        return jsonify({"status": "error", "message": "Input number 'n' is required."}), 400
        
    try:
        # Support hex or decimal string inputs
        n = int(n_str, 16) if n_str.startswith('0x') else int(n_str)
        
        start_time = time.time()
        trace = miller_rabin_trace(n, k)
        duration_ms = (time.time() - start_time) * 1000
        
        trace["time_ms"] = round(duration_ms, 2)
        
        return jsonify({
            "status": "success",
            "result": trace
        })
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid integer format."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
