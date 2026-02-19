import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'dev-key-please-change'
    
    # Firebase Configuration
    FIREBASE_PROJECT_ID = os.environ.get('FIREBASE_PROJECT_ID')
    FIREBASE_CLIENT_EMAIL = os.environ.get('FIREBASE_CLIENT_EMAIL')
    FIREBASE_PRIVATE_KEY = os.environ.get('FIREBASE_PRIVATE_KEY')
    FIREBASE_API_KEY = os.environ.get('FIREBASE_API_KEY')
    
    # WebAuthn Configuration
    # CRITICAL: RP_ID must be the effective domain (hostname) of the application.
    # It CANNOT include protocol (https://) or port.
    # On Render/Vercel, we must set RP_ID env var to the deployment domain (e.g., my-app.onrender.com)
    RP_ID = os.environ.get('RP_ID', 'localhost')
    RP_NAME = os.environ.get('RP_NAME', 'Cipherlock Vault')
    
    # Origin for CORS and WebAuthn verification
    # This should be the full URL of the frontend (e.g. https://my-app.vercel.app)
    ORIGIN = os.environ.get('ORIGIN', 'http://localhost:5173')
