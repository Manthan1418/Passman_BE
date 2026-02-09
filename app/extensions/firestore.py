from app.extensions.firebase import get_db

# Simple wrapper if we need to abstract firestore logic further
# Currently, just exposing the client is sufficient for the controller
def db_client():
    return get_db()
