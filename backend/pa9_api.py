# backend/pa9_api.py
from flask import Blueprint, request, Response, stream_with_context, jsonify
from Implementations.PA_9 import toy_hash, naive_birthday_attack
import json
import time

pa9_api = Blueprint('pa9_api', __name__)

@pa9_api.route('/start-birthday-attack/<int:n>', methods=['GET'])
def start_attack(n):
    """
    Starts the birthday attack for a given bit length n.
    Accepts n as a URL parameter, which is compatible with EventSource.
    """
    if not 8 <= n <= 24:
        return jsonify({"error": "Invalid bit length 'n'. Must be an integer between 8 and 24."}), 400

    def generate():
        """Generator function that yields attack progress as server-sent events."""
        
        # 1. FIX: Wrap the hash function so it knows the dynamic 'n' from the URL
        dynamic_hash = lambda msg: toy_hash(msg, n)
        
        # 2. FIX: Add yield_steps=True so it returns a generator, not a tuple!
        attack_generator = naive_birthday_attack(dynamic_hash, n, yield_steps=True)
        
        for result in attack_generator:
            yield f"data: {json.dumps({'type': 'attack_step', 'data': result})}\n\n"
            
            # Optional: Add a tiny delay for n=8 or n=10 so the UI doesn't finish in 1 millisecond
            if n <= 10:
                time.sleep(0.02)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')