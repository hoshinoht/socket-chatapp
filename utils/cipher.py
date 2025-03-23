"""Encryption utilities for secure socket communication."""
import base64
import sys
import time
import threading
from cryptography.fernet import Fernet

# Debug mode flag - enables verbose logging when --debug is passed as argument
DEBUG = "--debug" in sys.argv

def debug_print(message):
    """Print debug messages when DEBUG is True"""
    if DEBUG:
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        thread_id = threading.get_ident()
        print(f"[CIPHER DEBUG {timestamp}] [{thread_id}] {message}", file=sys.stderr, flush=True)

def get_fernet_key(key_bytes):
    """Generate a secure key for Fernet encryption from input seed."""
    debug_print(f"Generating Fernet key from seed: {key_bytes}")
    
    # Use SHA-256 to derive a 32-byte key, then encode to base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    salt = b'socketapp'  # A constant salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(key_bytes))

# Initialize encryption components
KEY_SEED = b'SecureSocketChat16'
debug_print("Initializing cipher module")
CIPHER_SUITE = Fernet(get_fernet_key(KEY_SEED))
debug_print("Cipher module initialized successfully")

def encrypt(plaintext):
    """Encrypt a message using Fernet (AES-128)."""
    # Convert to bytes if it's a string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Encrypt and return
    debug_print(f"Encrypting data, length: {len(plaintext)}")
    return CIPHER_SUITE.encrypt(plaintext)

def decrypt(ciphertext):
    """Decrypt a message using Fernet (AES-128)."""
    try:
        debug_print(f"Attempting to decrypt data of length: {len(ciphertext)}")
        decrypted = CIPHER_SUITE.decrypt(ciphertext)
        return decrypted.decode('utf-8')
    except Exception as e:
        debug_print(f"Decryption error: {e}")
        print(f"Decryption error: {e}")
        return None
