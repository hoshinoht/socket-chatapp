from utils.cipher import encrypt, decrypt
import unittest
import sys
import os
import socket
import threading
import time
import subprocess
import signal

# Add parent directory to path
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class MockServer:
  """A simple mock server for testing"""

  def __init__(self, host='127.0.0.1', port=0):
    self.host = host
    self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.server_socket.bind((host, port))
    self.actual_port = self.server_socket.getsockname()[1]
    self.is_running = False
    self.clients = []
    self.clients_lock = threading.Lock()  # Add a lock for thread safety

  def start(self):
    """Start the mock server"""
    self.is_running = True
    self.server_socket.listen(5)
    self.server_thread = threading.Thread(target=self._accept_connections)
    self.server_thread.daemon = True
    self.server_thread.start()
    return self.actual_port

  def _accept_connections(self):
    """Accept connections in a loop"""
    while self.is_running:
      try:
        # Short timeout to allow checking is_running
        self.server_socket.settimeout(0.5)
        client_socket, _ = self.server_socket.accept()
        with self.clients_lock:
          self.clients.append(client_socket)
        client_thread = threading.Thread(
            target=self._handle_client, args=(client_socket,))
        client_thread.daemon = True
        client_thread.start()
      except socket.timeout:
        continue
      except Exception as e:
        if self.is_running:  # Only log if we're supposed to be running
          print(f"Server accept error: {e}")
        break

  def _handle_client(self, client_socket):
    """Echo back messages from the client"""
    try:
      # Send username prompt
      client_socket.send("Username: ".encode())
      encrypted_username = client_socket.recv(2048)
      username = decrypt(encrypted_username)

      # Send password prompt
      client_socket.send("Password: ".encode())
      encrypted_password = client_socket.recv(2048)
      password = decrypt(encrypted_password)

      # Send welcome message
      welcome_msg = f"Welcome to the test server, {username}!"
      client_socket.send(encrypt(welcome_msg))

      # Echo messages
      while self.is_running:
        try:
          client_socket.settimeout(0.5)
          encrypted_message = client_socket.recv(2048)
          if not encrypted_message:
            break

          message = decrypt(encrypted_message)
          if message == "@quit":
            client_socket.send(encrypt("Goodbye!"))
            break

          # Echo back
          response = f"Echo: {message}"
          client_socket.send(encrypt(response))
        except socket.timeout:
          continue
        except Exception as e:
          print(f"Client communication error: {e}")
          break
    finally:
      try:
        client_socket.close()
      except:
        pass
      # Thread-safe removal of client from list
      with self.clients_lock:
        if client_socket in self.clients:
          self.clients.remove(client_socket)

  def stop(self):
    """Stop the mock server"""
    self.is_running = False
    # Close all client connections
    with self.clients_lock:
      clients_copy = self.clients.copy()  # Create a copy to iterate over

    for client in clients_copy:
      try:
        client.close()
      except:
        pass

    # Clear the clients list
    with self.clients_lock:
      self.clients.clear()  # Simply clear the list instead of individual removes

    # Close server socket
    try:
      self.server_socket.close()
    except:
      pass


class TestClientServerIntegration(unittest.TestCase):
  """Basic integration tests for the client and server"""

  @classmethod
  def setUpClass(cls):
    """Start a mock server for the tests"""
    cls.mock_server = MockServer()
    cls.server_port = cls.mock_server.start()
    time.sleep(0.5)  # Give the server time to start

  @classmethod
  def tearDownClass(cls):
    """Stop the mock server"""
    cls.mock_server.stop()

  def test_client_connection_basic(self):
    """Test basic client connection using sockets directly"""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', self.server_port))

    # Get username prompt and respond
    prompt = client.recv(2048).decode()
    self.assertEqual(prompt, "Username: ")
    client.send(encrypt("testuser"))

    # Get password prompt and respond
    prompt = client.recv(2048).decode()
    self.assertEqual(prompt, "Password: ")
    client.send(encrypt("testpass"))

    # Get welcome message
    encrypted_welcome = client.recv(2048)
    welcome = decrypt(encrypted_welcome)
    self.assertEqual(welcome, "Welcome to the test server, testuser!")

    # Send a test message
    client.send(encrypt("Hello, server!"))

    # Get echo response
    encrypted_response = client.recv(2048)
    response = decrypt(encrypted_response)
    self.assertEqual(response, "Echo: Hello, server!")

    # Clean up
    client.close()


class TestRealServerCommands(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.server_process = subprocess.Popen(
        [sys.executable, "server/server.py", "127.0.0.1", "9999"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(1)  # Give server time to start

  @classmethod
  def tearDownClass(cls):
    cls.server_process.terminate()
    cls.server_process.wait()

  def test_names_command(self):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9999))
    # Log in as "tester"
    prompt = client.recv(2048).decode()
    self.assertIn("Username:", prompt)
    client.send(encrypt("tester"))

    prompt = client.recv(2048).decode()
    self.assertIn("Password:", prompt)
    client.send(encrypt("password"))

    # Receive welcome
    welcome = decrypt(client.recv(2048))
    self.assertIn("Welcome to the chatroom", welcome)

    # Test @names command
    client.send(encrypt("@names"))
    response = decrypt(client.recv(2048))
    self.assertIn("Online users:", response)

    client.close()


if __name__ == "__main__":
  unittest.main()
