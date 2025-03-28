from utils.cipher import encrypt, decrypt
import unittest
import sys
import os

# Add parent directory to path to import cipher
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class TestCipher(unittest.TestCase):
  """Test suite for the encryption/decryption functionality"""

  def test_string_encryption_decryption(self):
    """Test that a string can be encrypted and then decrypted correctly"""
    original_text = "Hello, secure chat!"
    encrypted = encrypt(original_text)
    decrypted = decrypt(encrypted)
    self.assertEqual(original_text, decrypted)

  def test_bytes_encryption_decryption(self):
    """Test that byte data can be encrypted and then decrypted correctly"""
    original_bytes = b"Hello, bytes data!"
    encrypted = encrypt(original_bytes)
    decrypted = decrypt(encrypted)
    self.assertEqual(original_bytes.decode('utf-8'), decrypted)

  def test_empty_string(self):
    """Test encryption and decryption of an empty string"""
    original = ""
    encrypted = encrypt(original)
    decrypted = decrypt(encrypted)
    self.assertEqual(original, decrypted)

  def test_special_characters(self):
    """Test encryption and decryption of special characters"""
    original = "!@#$%^&*()_+{}|:<>?[];',./©®€™"
    encrypted = encrypt(original)
    decrypted = decrypt(encrypted)
    self.assertEqual(original, decrypted)

  def test_long_message(self):
    """Test encryption and decryption of a long message"""
    original = "A" * 10000  # 10KB string
    encrypted = encrypt(original)
    decrypted = decrypt(encrypted)
    self.assertEqual(original, decrypted)

  def test_invalid_ciphertext(self):
    """Test decryption of invalid ciphertext returns None"""
    invalid_data = b"NotValidCiphertext"
    result = decrypt(invalid_data)
    self.assertIsNone(result)


if __name__ == "__main__":
  unittest.main()
