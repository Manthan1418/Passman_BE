import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

db = None

def init_firebase(app):
    global db
    
    # Check if already initialized
    if not firebase_admin._apps:
        # Load credentials from env vars
        private_key = app.config['FIREBASE_PRIVATE_KEY']
        if private_key:
            # Handle various common formatting issues with env var private keys
            private_key = private_key.replace('\\n', '\n') # Handle literal \n characters
            if not private_key.startswith('-----BEGIN PRIVATE KEY-----'):
                 # Try to fix missing headers if they got stripped
                 pass 
        
        cred_dict = {
            "type": "service_account",
            "project_id": app.config['FIREBASE_PROJECT_ID'],
            "private_key_id": "dummy_key_id",
            "private_key": private_key,
            "client_email": app.config['FIREBASE_CLIENT_EMAIL'],
            "client_id": "dummy_client_id",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{app.config['FIREBASE_CLIENT_EMAIL']}"
        }

        # Validate critical fields
        if not cred_dict['project_id'] or not cred_dict['private_key'] or not cred_dict['client_email']:
            print("ERROR: Missing Firebase credentials in .env")
            print(f"Project ID: {cred_dict['project_id']}")
            print(f"Client Email: {cred_dict['client_email']}")
            print(f"Private Key Present: {bool(cred_dict['private_key'])}")
            if not cred_dict['private_key']:
                 print("Hint: Check FLASK_PRIVATE_KEY / FIREBASE_PRIVATE_KEY in .env")
            return

        try:
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin Initialized Successfully")
        except Exception as e:
            print(f"Failed to initialize Firebase Admin: {e}")
            print("Check your FIREBASE_PRIVATE_KEY format in .env.")
            # Don't crash app, but routes might fail

    
    db = firestore.client()

def get_db():
    return db
