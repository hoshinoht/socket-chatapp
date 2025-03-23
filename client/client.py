"""
Client application for encrypted socket chat.
Features:
- Secure encrypted communication
- Multi-threaded design for simultaneous send/receive
- Command processing (@names, @group, etc.)
"""
import socket
import sys
import os
import time
import threading

# Add parent directory to path to import cipher
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.cipher import encrypt, decrypt

# Parse command line arguments for debug mode
DEBUG = "--debug" in sys.argv
args = [arg for arg in sys.argv if arg != "--debug"]
if DEBUG:
    print("Debug mode enabled")

def debug_print(message):
    """Print debug messages with timestamp when DEBUG is True"""
    if DEBUG:
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        print(f"[DEBUG {timestamp}] {message}", file=sys.stderr, flush=True)

# Command line argument validation
if len(args) != 3:
    print("Usage: script IP_address port [--debug]")
    sys.exit()
IP_address = str(args[1])
Port = int(args[2])

# Initialize socket connection
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server.connect((IP_address, Port))
except ConnectionRefusedError:
    print(f"Unable to connect to server at {IP_address}:{Port}")
    sys.exit()
except Exception as e:
    print(f"Connection error: {e}")
    sys.exit()

# --- Authentication Phase ---
try:
    # Get username
    sys.stdout.write(server.recv(2048).decode())
    sys.stdout.flush()
    username = input()
    server.send(encrypt(username))

    # Get password
    sys.stdout.write(server.recv(2048).decode())
    sys.stdout.flush()
    password = input()
    server.send(encrypt(password))

    # Check response
    response = decrypt(server.recv(2048))
    if response.startswith("ERROR"):
        print(response)
        server.close()
        sys.exit()
    print(response)
except Exception as e:
    print(f"Error during authentication: {e}")
    server.close()
    sys.exit()

# Global state
running = True
prompt = f"[{username}] "

def show_prompt():
    """Display the user prompt"""
    sys.stdout.write(prompt)
    sys.stdout.flush()

def receive_messages():
    """Background thread to receive and display messages from server"""
    global running
    debug_print("Receive thread started")
    
    while running:
        try:
            encrypted_message = server.recv(2048)
            if not encrypted_message:
                print("\nConnection closed by server")
                running = False
                break
            
            # Decrypt and display
            message = decrypt(encrypted_message)
            sys.stdout.write("\r" + " " * len(prompt) + "\r")  # Clear prompt
            print(message, end='')
            show_prompt()  # Re-show the prompt
        except Exception as e:
            print(f"\nError receiving: {e}")
            running = False
    
    debug_print("Receive thread ended")

def send_messages():
    """Get user input and send messages to server"""
    global running
    show_prompt()  # Show initial prompt
    
    while running:
        try:
            user_input = input()
            
            if not running:
                break
            
            if user_input:
                # Send encrypted message
                server.send(encrypt(user_input))
                
            # Show the prompt again
            show_prompt()
        except (KeyboardInterrupt, EOFError):
            running = False
            break
        except Exception as e:
            print(f"\nInput error: {e}")
            time.sleep(0.1)

# Start the receive thread
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Main loop
try:
    send_messages()  # Run in the main thread
except KeyboardInterrupt:
    print("\nDisconnecting...")
except Exception as e:
    print(f"Error: {e}")
finally:
    # Clean up
    running = False
    server.close()
    time.sleep(0.5)

