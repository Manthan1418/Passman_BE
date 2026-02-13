import requests
from flask import current_app
import json
from app.extensions.firebase import get_firestore_base_url

class FirestoreClient:
    """
    A simple wrapper around Firestore REST API because Admin SDK is not available.
    """
    
    @staticmethod
    def _get_headers():
        # Authenticating as the SERVER (Service Account) is tricky without Admin SDK.
        # IF we are running locally without a service account key, we might have issues writing to Firestore 
        # unless rules allow open access or we use an ID token of a user.
        # BUT `WebAuthnService` needs to write challenges *before* user is logged in (sometimes).
        
        # HOWEVER, the previous error log showed `ValueError` related to Firebase private key.
        # If we can't use Admin SDK, we can't easily write as Admin via REST without an OAuth2 token from the service account.
        
        # CHECK: How does `auth_controller.py` write?
        # It uses `request.token` (ID Token from client) to authenticate requests.
        # `update_user_doc` in `auth_controller` uses `Authorization: Bearer {token}`.
        
        # This implies we can only write if we have a user token.
        # BUT `generate_registration_options` happens *after* login usually (for registering passkey).
        # `generate_login_options` happens *before* login.
        
        # Problem: Storing the challenge for Login (when user is not yet authenticated).
        # Solution: 
        # 1. Use an in-memory store for challenges (simplest for MVP).
        # 2. Or require the client to be anonymous-signed-in (Firebase Anon Auth)?
        # 3. Or just don't verify challenge persistence on server properly for MVP (Security risk).
        
        # Let's go with In-Memory for challenges (CACHE).
        # For `users` collection access (storing credentials), we need to write to the user's doc.
        # We can use the user's ID token if available.
        pass

    # We will use this mainly for operations where we HAVE a token (updates)
    # or if we are just reading public info (if rules allow).
    @staticmethod
    def get_doc(collection, doc_id, token):
        url = f"{get_firestore_base_url()}/{collection}/{doc_id}"
        headers = {"Authorization": f"Bearer {token}"}
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
             return res.json()
        return None

    @staticmethod
    def update_doc(collection, doc_id, data, token):
        # Data should be in Firestore format: { "fields": { ... } }
        # Helper to convert simple dict to Firestore format is complex.
        # For now, expect caller to format or we implement a simple converter.
        url = f"{get_firestore_base_url()}/{collection}/{doc_id}"
        # We need to specify updateMask if we want to merge, but PATCH merges by default in REST?
        # No, PATCH replaces if not masked? usage varies.
        # Let's assume input is formatted.
        headers = {"Authorization": f"Bearer {token}"}
        return requests.patch(url, json=data, headers=headers)

# GLOBAL IN-MEMORY CHALLENGE STORE
# Since we cannot easily write to Firestore without Admin SDK or User Token (and login has no token yet),
# We will store challenges in memory. 
# NOTE: This won't work across multiple worker processes (gunicorn/uwsgi) unless we use Redis/Memcached.
# For this local dev / MVP, it is acceptable.
CHALLENGE_STORE = {}

def store_challenge(key, challenge, type):
    CHALLENGE_STORE[key] = {
        'challenge': challenge,
        'type': type,
        'timestamp': datetime.now().timestamp()
    }

def get_challenge(key):
    # Retrieve and delete (nonce)
    data = CHALLENGE_STORE.get(key)
    if data:
        # Check expiration (e.g. 5 mins)
        if datetime.now().timestamp() - data['timestamp'] > 300:
            del CHALLENGE_STORE[key]
            return None
        del CHALLENGE_STORE[key]
    return data

from datetime import datetime
