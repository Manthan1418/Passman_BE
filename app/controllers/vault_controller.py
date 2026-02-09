from flask import request, jsonify
from app.extensions.firestore import db_client
from google.cloud.firestore_v1.base_query import FieldFilter

def add_password():
    uid = request.uid
    data = request.json
    
    # Validation: Ensure ONLY encrypted blobs are being sent
    required_fields = ['site', 'username', 'encryptedPassword', 'iv']
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Store in Firestore under users/{uid}/vault
    # Backend DOES NOT ENCRYPT OR DECRYPT. It just stores.
    doc_ref = db_client().collection('users').document(uid).collection('vault').document()
    doc_ref.set({
        'site': data['site'],
        'username': data['username'],
        'encryptedPassword': data['encryptedPassword'],
        'iv': data['iv'],
        'createdAt': firestore_timestamp(),
        'updatedAt': firestore_timestamp()
    })
    
    return jsonify({'id': doc_ref.id, 'message': 'Password stored successfully'}), 201

def get_passwords():
    uid = request.uid
    vault_ref = db_client().collection('users').document(uid).collection('vault')
    docs = vault_ref.stream()
    
    results = []
    for doc in docs:
        item = doc.to_dict()
        item['id'] = doc.id
        results.append(item)
        
    return jsonify(results), 200

def delete_password(entry_id):
    uid = request.uid
    # Ensure the document belongs to the user
    doc_ref = db_client().collection('users').document(uid).collection('vault').document(entry_id)
    doc_ref.delete()
    
    return jsonify({'message': 'Password deleted'}), 200

def firestore_timestamp():
    from datetime import datetime
    return datetime.utcnow()
