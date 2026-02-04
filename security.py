import os
import secrets
import hashlib
import base64
import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- 1. Key Management (RSA) ---

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(BASE_DIR, "keys")

def generate_rsa_keys():
    """Generates RSA public and private keys if they don't exist."""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
    
    private_key_path = os.path.join(KEY_DIR, "private.pem")
    public_key_path = os.path.join(KEY_DIR, "public.pem")

    if not os.path.exists(private_key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Save Private Key
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save Public Key
        public_key = private_key.public_key()
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("RSA Keys generated.")
    else:
        print("RSA Keys already exist.")

def load_private_key():
    with open(os.path.join(KEY_DIR, "private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    with open(os.path.join(KEY_DIR, "public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())

# --- 2. Authentication (Hashing & OTP) ---

def hash_password(password):
    """Hashes a password using bcrypt with salt."""
    # bcrypt automatically handles salting
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password, hashed_password):
    """Verifies a password against the stored hash."""
    # hashed_password might be a string from DB, so encode it back to bytes for bcrypt
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def generate_otp():
    """Generates a secure 6-digit OTP."""
    return str(secrets.randbelow(1000000)).zfill(6)

# --- 3. Encryption (AES & RSA) ---

def encrypt_data_aes(data):
    """
    Encrypts data using a fresh AES key (Symmetric).
    Returns: 
        - encrypted_data (base64 str)
        - aes_key (bytes, raw)
    """
    aes_key = os.urandom(32) # 256-bit key
    iv = os.urandom(16)      # 128-bit IV
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    
    # Prepend IV to ciphertext for storage
    full_encrypted = iv + ciphertext
    return base64.b64encode(full_encrypted).decode('utf-8'), aes_key

def decrypt_data_aes(encoded_encrypted_data, aes_key):
    """Decrypts base64 encoded AES encrypted data."""
    encrypted_bytes = base64.b64decode(encoded_encrypted_data)
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

def encrypt_key_rsa(aes_key):
    """Encrypts the AES key using the System's RSA Public Key."""
    public_key = load_public_key()
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_key_rsa(encoded_encrypted_key):
    """Decrypts the AES key using the System's RSA Private Key."""
    private_key = load_private_key()
    encrypted_key_bytes = base64.b64decode(encoded_encrypted_key)
    
    aes_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# --- 4. Hashing & Integrity ---

def generate_integrity_hash(data):
    """Generates a SHA-256 hash of the data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def sign_hash(data_hash):
    """Signs the hash using the System's RSA Private Key."""
    private_key = load_private_key()
    # For signing, we usually sign the bytes. 
    # Here we sign the hash string bytes.
    signature = private_key.sign(
        data_hash.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data_hash, encoded_signature):
    """Verifies the signature using the System's RSA Public Key."""
    public_key = load_public_key()
    signature_bytes = base64.b64decode(encoded_signature)
    
    try:
        public_key.verify(
            signature_bytes,
            data_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
