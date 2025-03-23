"""
Multi-threaded chat server with encrypted communication.
Features:
- User authentication
- Group messaging
- Direct messaging
- Message history tracking
- Thread-safe data access
"""
import socket
import select
import sys
from _thread import start_new_thread
import threading
import time
import traceback
import os

# Add parent directory to path to import cipher
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.cipher import encrypt, decrypt

# Parse command line arguments for debug mode
DEBUG = "--debug" in sys.argv
args = [arg for arg in sys.argv if arg != "--debug"]
if DEBUG:
    print("Debug mode enabled")

def debug_print(message, username="SERVER"):
    """Print debug messages with timestamp, username and thread ID"""
    if DEBUG:
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        thread_id = threading.get_ident()
        print(f"[DEBUG {timestamp}] [{username}] [{thread_id}] {message}")

# Global data structures
credentials = {}   # username -> password
clients = {}       # username -> connection
groups = {}        # group_name -> set of usernames
history = {}       # username -> list of messages (limited to last 50)

# Thread-safe lock for accessing shared data
lock = threading.Lock()

def send_to_client(username, message):
    """Send an encrypted message to a specific user and log it in their history."""
    try:
        if username in clients:
            # Ensure message ends with newline
            if not message.endswith('\n'):
                message += '\n'
            
            # Encrypt and send
            clients[username].send(encrypt(message))
            
            # Update history
            with lock:
                if username in history:
                    history[username].append(message)
                    if len(history[username]) > 50:
                        history[username] = history[username][-50:]
                else:
                    history[username] = [message]
    except Exception as e:
        debug_print(f"Error sending to {username}: {e}", username)

def broadcast(message, exclude_conn=None):
    """Broadcast a message to all connected clients except the excluded one."""
    if not message.endswith('\n'):
        message += '\n'
    
    with lock:
        clients_copy = list(clients.items())
        
    for user, conn in clients_copy:
        if conn != exclude_conn:
            try:
                conn.send(encrypt(message))
                
                # Update history
                with lock:
                    if user in history:
                        history[user].append(message)
                        if len(history[user]) > 50:
                            history[user] = history[user][-50:]
                    else:
                        history[user] = [message]
            except Exception as e:
                debug_print(f"Error broadcasting to {user}: {e}")
                try:
                    conn.close()
                except:
                    pass
                remove(conn)

def remove(conn):
    """Remove a client connection from the server."""
    with lock:
        for user, client_conn in list(clients.items()):
            if client_conn == conn:
                del clients[user]
                debug_print(f"Removed user: {user}")
                return user
        return None

def handle_command(username, message_str, conn):
    """
    Process a command from a client.
    Returns True if command was processed, False otherwise.
    """
    if not message_str.startswith('@'):
        return False
        
    # Command: Quit
    if message_str == "@quit":
        send_to_client(username, "Goodbye!\n")
        return True
    
    # Command: List users
    if message_str == "@names":
        with lock:
            names_list = ", ".join(clients.keys())
        send_to_client(username, "Online users: " + names_list + "\n")
        return True
    
    # Command: View history
    if message_str.startswith('@history'):
        parts = message_str.split()
        if len(parts) != 2:
            send_to_client(username, "Usage: @history <number>\n")
            return True
            
        try:
            N = int(parts[1])
            with lock:
                user_hist = history.get(username, [])[:]
                
            hist_msg = "\n--- Last {} Messages ---\n".format(min(N, len(user_hist)))
            hist_msg += "\n".join(user_hist[-N:])
            send_to_client(username, hist_msg + "\n")
        except ValueError:
            send_to_client(username, "ERROR: Please provide a valid number.\n")
        return True
    
    # Command: Direct message
    if message_str[1:].find(' ') != -1 and not message_str.startswith('@group'):
        target, msg_text = message_str[1:].split(' ', 1)
        
        with lock:
            target_exists = target in clients
        
        if target_exists:
            send_to_client(target, "[DM from " + username + "]: " + msg_text + "\n")
            send_to_client(username, "[DM to " + target + "]: " + msg_text + "\n")
        else:
            send_to_client(username, "ERROR: User " + target + " not online.\n")
        return True
    
    # Command: Group operations
    if message_str.startswith('@group'):
        parts = message_str.split(' ', 2)
        if len(parts) < 2:
            send_to_client(username, "ERROR: Invalid group command.\n")
            return True
            
        subcmd = parts[1]
        
        # Group: Create
        if subcmd == "set" and len(parts) >= 3 and ' ' in parts[2]:
            group_name, members_str = parts[2].split(' ', 1)
            members = [m.strip() for m in members_str.split(',') if m.strip()]
            members.append(username)
            
            with lock:
                group_exists = group_name in groups
                not_online = [] if not group_exists else []
                if not group_exists:
                    not_online = [m for m in members if m not in clients]
            
            if group_exists:
                send_to_client(username, "ERROR: Group " + group_name + " already exists.\n")
            elif not_online:
                send_to_client(username, "ERROR: These users not online: " + ", ".join(not_online) + "\n")
            else:
                with lock:
                    groups[group_name] = set(members)
                send_to_client(username, "Group " + group_name + " created with members: " + 
                              ", ".join(members) + "\n")
            return True
        
        # Group: Send message
        elif subcmd == "send" and len(parts) >= 3 and ' ' in parts[2]:
            group_name, group_msg = parts[2].split(' ', 1)
            
            with lock:
                group_exists = group_name in groups
                is_member = group_exists and username in groups[group_name]
                member_list = list(groups[group_name]) if is_member else []
            
            if not group_exists:
                send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
            elif not is_member:
                send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
            else:
                full_msg = "[Group: " + group_name + "] " + username + ": " + group_msg + "\n"
                for member in member_list:
                    with lock:
                        member_connected = member in clients
                    if member_connected:
                        send_to_client(member, full_msg)
            return True
        
        # Group: Leave
        elif subcmd == "leave" and len(parts) >= 3:
            group_name = parts[2].strip()
            
            with lock:
                group_exists = group_name in groups
                is_member = group_exists and username in groups[group_name]
                if is_member:
                    groups[group_name].remove(username)
            
            if not group_exists:
                send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
            elif not is_member:
                send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
            else:
                send_to_client(username, "You left group " + group_name + ".\n")
            return True
        
        # Group: Delete
        elif subcmd == "delete" and len(parts) >= 3:
            group_name = parts[2].strip()
            
            with lock:
                group_exists = group_name in groups
                is_member = group_exists and username in groups[group_name]
                if is_member:
                    del groups[group_name]
            
            if not group_exists:
                send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
            elif not is_member:
                send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
            else:
                send_to_client(username, "Group " + group_name + " deleted.\n")
            return True
        
        # Unknown group command
        else:
            send_to_client(username, "ERROR: Unknown or invalid group command.\n")
            return True
    
    # Unknown command
    send_to_client(username, "ERROR: Unknown command.\n")
    return True

def clientthread(conn, addr):
    """Handle a client connection in a dedicated thread."""
    username = ""
    try:
        # --- Authentication Phase ---
        conn.send("Username: ".encode())  # Initial prompt unencrypted
        encrypted_username = conn.recv(2048)
        username = decrypt(encrypted_username).strip()
        if not username:
            conn.close()
            return
            
        conn.send("Password: ".encode())  # Password prompt unencrypted
        encrypted_password = conn.recv(2048)
        password = decrypt(encrypted_password).strip()
        if not password:
            conn.close()
            return

        # Authenticate or register
        with lock:
            if username in credentials:
                if credentials[username] != password:
                    conn.send(encrypt("ERROR: Incorrect password.\n"))
                    conn.close()
                    return
            else:
                credentials[username] = password

            if username in clients:
                conn.send(encrypt("ERROR: User already logged in.\n"))
                conn.close()
                return
            clients[username] = conn
            if username not in history:
                history[username] = []

        # Welcome messages
        send_to_client(username, "Welcome to the chatroom, " + username + "!")
        broadcast("* " + username + " has joined the chat *", conn)
        print(username, "connected from", addr)

        # --- Main Communication Loop ---
        while True:
            try:
                ready = select.select([conn], [], [], 1)
                if ready[0]:
                    encrypted_message = conn.recv(2048)
                    if not encrypted_message:
                        break
                    
                    message_str = decrypt(encrypted_message).strip()
                    if not message_str:
                        continue
                    
                    # Process commands or broadcast message
                    if message_str.startswith('@'):
                        if handle_command(username, message_str, conn):
                            if message_str == "@quit":  # User quit
                                break
                            continue
                    
                    # Regular message
                    broadcast(username + ": " + message_str, conn)
                        
            except Exception as e:
                debug_print(f"Exception with {username}: {e}", username)
                break
                
    except Exception as ex:
        debug_print(f"Error with client {addr}: {ex}")
    finally:
        # Clean up
        with lock:
            if username in clients:
                del clients[username]
        broadcast(f"* {username} has left the chat *\n", conn)
        conn.close()

def main():
    """Main server function."""
    # Check arguments
    if len(args) != 3:
        print("Usage: script IP_address port [--debug]")
        sys.exit()
    IP_address = str(args[1])
    Port = int(args[2])
    
    # Initialize server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((IP_address, Port))
        server.listen(100)
        print("Server started on", IP_address, "port", Port)
        
        # Main accept loop
        while True:
            try:
                conn, addr = server.accept()
                print(addr[0], "connected")
                start_new_thread(clientthread, (conn, addr))
            except KeyboardInterrupt:
                print("\nShutting down server...")
                break
            except Exception as e:
                debug_print(f"Error accepting connection: {e}")
                
    except Exception as e:
        debug_print(f"Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    main()
