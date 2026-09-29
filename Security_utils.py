import hashlib
import os
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import json

def encode_base64(data: dict) -> str:
    json_str = json.dumps(data)           
    b64_bytes = base64.urlsafe_b64encode(json_str.encode('utf-8'))#converts the JSON string into bytes
    return b64_bytes.decode('utf-8')#Converts the Base64 bytes back into a regular string.

def decode_base64(b64_str: str) -> dict:
 
    json_bytes = base64.urlsafe_b64decode(b64_str.encode('utf-8'))#converts the Base64 string into bytes.
    return json.loads(json_bytes.decode('utf-8'))#Converts the bytes back into a JSON string and then parses it into a dictionary.

# 1. HASHING WITH SALT 
def hash_password(password: str):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # iterations
    )
    return salt.hex(), hashed.hex()


def verify_password(password: str, salt_hex: str, stored_hash_hex: str):
    salt = bytes.fromhex(salt_hex)
    stored_hash = bytes.fromhex(stored_hash_hex)
    
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return new_hash == stored_hash


# 2. DIGITAL SIGNATURES

class DigitalSignatureManager:
    
    def __init__(self, private_key_path='private_key.pem', public_key_path='public_key.pem'):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.private_key = None
        self.public_key = None
        
        # Load or generate keys
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            self.load_keys()
        else:
            self.generate_keys()
    
   
    
    def load_keys(self):
        with open(self.private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(self.public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    
    def sign_data(self, data):
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
    
    def verify_signature(self, data, signature_hex: str):
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        signature = bytes.fromhex(signature_hex)
        
        try:
            self.public_key.verify(
                signature,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def hash_data(self, data):
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        return hashlib.sha256(data_bytes).hexdigest()


# 3. UTILITY FUNCTIONS FOR APPOINTMENTS

def create_appointment_signature(appointment_data, signature_manager):
    # Create a hash of critical fields
    critical_data = {
        'patient_id': appointment_data.get('patient_id'),
        'doctor_id': appointment_data.get('doctor_id'),
        'date': appointment_data.get('date'),
        'time': appointment_data.get('time'),
        'reason': appointment_data.get('reason')
    }
    
    signature = signature_manager.sign_data(critical_data)
    data_hash = signature_manager.hash_data(critical_data)
    
    return {
        'signature': signature,
        'hash': data_hash,
        'signed_fields': list(critical_data.keys())
    }


def verify_appointment_integrity(appointment_data, stored_signature, stored_hash, signature_manager):
 
    # Reconstruct critical data
    critical_data = {
        'patient_id': appointment_data.get('patient_id'),
        'doctor_id': appointment_data.get('doctor_id'),
        'date': appointment_data.get('date'),
        'time': appointment_data.get('time'),
        'reason': appointment_data.get('reason')
    }
    
    # Verify hash
    current_hash = signature_manager.hash_data(critical_data)
    if current_hash != stored_hash:
        return False, "Data integrity check failed - data has been modified"
    
    # Verify signature
    is_valid = signature_manager.verify_signature(critical_data, stored_signature)
    if not is_valid:
        return False, "Digital signature verification failed - authenticity cannot be confirmed"
    
    return True, "Appointment data is authentic and unmodified"
