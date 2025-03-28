import base64
import os
import sys
import time
import threading

# Use the standard Python cryptography library which is more commonly available
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Debug mode flag
DEBUG = False
if "--debug" in sys.argv:
  DEBUG = True


def debug_print(message):
  """Print debug messages when DEBUG is True"""
  if DEBUG:
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    thread_id = threading.get_ident()
    print(f"[CIPHER DEBUG {timestamp}] [{thread_id}] {message}",
          file=sys.stderr, flush=True)

# Create a proper Fernet key (must be 32 url-safe base64-encoded bytes)
# We'll derive a proper key from our existing key string


def get_fernet_key(key_bytes):
  debug_print(f"Generating Fernet key from seed: {key_bytes}")

  salt = b'socketapp'  # A constant salt (could be made more secure)
  debug_print(f"Using salt: {salt}")

  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=100000,
  )
  key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
  debug_print(f"Generated key: {key[:10]}... (first 10 bytes shown)")
  return key


# Use our original key as a seed to generate a proper Fernet key
KEY_SEED = b'SecureSocketChat16'  # Original key as seed
debug_print("Initializing cipher module")
FERNET_KEY = get_fernet_key(KEY_SEED)
CIPHER_SUITE = Fernet(FERNET_KEY)
debug_print("Cipher module initialized successfully")


def encrypt(plaintext):
  """
  Encrypt a message using Fernet (AES-128)
  """
  # Convert to bytes if it's a string
  if isinstance(plaintext, str):
    debug_print(f"Converting string to bytes, length: {len(plaintext)}")
    plaintext = plaintext.encode('utf-8')
  else:
    debug_print(f"Input is already bytes, length: {len(plaintext)}")

  # Encrypt and return as base64
  debug_print("Encrypting data")
  encrypted = CIPHER_SUITE.encrypt(plaintext)
  debug_print(f"Encryption complete, encrypted length: {len(encrypted)}")
  return encrypted


def decrypt(ciphertext):
  """
  Decrypt a message using Fernet (AES-128)
  """
  try:
    debug_print(f"Attempting to decrypt data of length: {len(ciphertext)}")
    # Decrypt the message
    decrypted = CIPHER_SUITE.decrypt(ciphertext)

    # Return as string
    debug_print(f"Decryption successful, decrypted length: {len(decrypted)}")
    result = decrypted.decode('utf-8')
    debug_print(f"Decoded to string, length: {len(result)}")
    return result
  except Exception as e:
    debug_print(f"Decryption error: {e}")
    print(f"Decryption error: {e}")
    return None
