from functools import wraps
from flask import request, jsonify
from firebase_admin import auth

def verify_firebase_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No Authorization header provided'}), 401

        try:
            token = auth_header.split(" ")[1]
            decoded_token = auth.verify_id_token(token)
            request.uid = decoded_token['uid']
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token', 'details': str(e)}), 401

        return f(*args, **kwargs)
    return decorated_function
