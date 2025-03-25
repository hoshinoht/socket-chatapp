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
DEBUG = False
args = sys.argv[:]
if "--debug" in args:
    DEBUG = True
    args.remove("--debug")
    print("Debug mode enabled")

# Flag to indicate if the server is running
server_running = True

# Helper function to check if msvcrt is available (Windows)
def msvcrt_available():
    try:
        import msvcrt
        return True
    except ImportError:
        return False

def debug_print(message, username="SERVER"):
    if DEBUG:
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        thread_id = threading.get_ident()
        print(f"[DEBUG {timestamp}] [{username}] [{thread_id}] {message}")

# Global data structures
credentials = {}   # username -> password
clients = {}       # username -> connection
groups = {}        # group_name -> set of usernames
history = {}       # username -> list of messages

# Create a custom debug lock class instead of modifying the lock directly
class DebugLock:
    def __init__(self):
        self._lock = threading.Lock()
        self.holder = None
        self.acquire_time = 0
        
    def acquire(self, blocking=True, timeout=-1):
        result = self._lock.acquire(blocking, timeout)
        if DEBUG and result:
            caller = traceback.extract_stack()[-2]
            debug_print(f"Attempting to acquire lock at {caller.filename}:{caller.lineno}")
            self.holder = threading.get_ident()
            self.acquire_time = time.time()
            debug_print(f"Lock acquired by thread {self.holder}")
        return result
        
    def release(self):
        if DEBUG:
            caller = traceback.extract_stack()[-2]
            debug_print(f"Releasing lock at {caller.filename}:{caller.lineno}")
            if self.acquire_time:
                hold_time = time.time() - self.acquire_time
                debug_print(f"Lock was held for {hold_time:.6f} seconds")
            self.holder = None
            self.acquire_time = 0
        return self._lock.release()
    
    def __enter__(self):
        self.acquire()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

# Create our debug lock
lock = DebugLock()

# Helper: send message to a specific user and log it in their history.
def send_to_client(username, message):
    try:
        debug_print(f"Sending message to {username}: {message.strip()}", username)
        if username in clients:
            # Ensure message ends with newline for proper display
            if not message.endswith('\n'):
                message += '\n'
            
            # Encrypt message before sending
            encrypted_message = encrypt(message)
            
            # Send message in chunks to prevent buffer issues
            try:
                debug_print(f"Using sendall to {username}", username)
                clients[username].sendall(encrypted_message)
                debug_print(f"sendall successful to {username}", username)
            except Exception as sendall_error:
                debug_print(f"sendall failed, using regular send: {sendall_error}", username)
                # Fall back to regular send if sendall fails
                clients[username].send(encrypted_message)
                debug_print(f"regular send successful to {username}", username)
    except Exception as e:
        debug_print(f"Error sending to {username}: {e}", username)
    
    # Append message to user's history (limit to 50 entries)
    with lock:
        debug_print(f"Updating history for {username}", username)
        if username in history:
            history[username].append(message)
            if len(history[username]) > 50:
                history[username] = history[username][-50:]
        else:
            history[username] = [message]
        debug_print(f"History updated for {username}", username)

def broadcast(message, exclude_conn=None):
    if not message.endswith('\n'):
        message += '\n'
    
    debug_print(f"Broadcasting: {message.strip()}")
    
    with lock:
        debug_print(f"In broadcast critical section, clients count: {len(clients)}")
        clients_copy = list(clients.items())  # Make a copy to avoid dict changes during iteration
        
    for user, conn in clients_copy:
        if conn != exclude_conn:
            try:
                debug_print(f"Sending broadcast to {user}")
                # Encrypt the message before broadcasting
                encrypted_message = encrypt(message)
                conn.send(encrypted_message)
                debug_print(f"Broadcast sent to {user}")
                
                # Update history
                with lock:
                    debug_print(f"Updating broadcast history for {user}")
                    if user in history:
                        history[user].append(message)
                        if len(history[user]) > 50:
                            history[user] = history[user][-50:]
                    else:
                        history[user] = [message]
            except Exception as e:
                debug_print(f"Error broadcasting to {user}: {e}")
                # Close and remove failed connections
                try:
                    conn.close()
                    debug_print(f"Closed connection for {user} after broadcast error")
                except:
                    pass
                remove(conn)

def remove(conn):
    """Remove a client connection without affecting other connections with the same username"""
    with lock:
        debug_print("In remove critical section")
        removed_user = None
        for user, client_conn in list(clients.items()):
            if client_conn == conn:
                removed_user = user
                del clients[user]
                debug_print(f"Removed user: {user}")
                break
        return removed_user


def clientthread(conn, addr):
    username = ""
    try:
        # --- Authentication Phase ---
        debug_print(f"New connection from {addr}, starting authentication")
        conn.send("Username: ".encode())  # Initial prompt unencrypted
        encrypted_username = conn.recv(2048)
        username = decrypt(encrypted_username).strip()
        if not username:
            conn.close()
            # throw an exception for invalid username
            raise Exception("Invalid username")
            
        conn.send("Password: ".encode())  # Password prompt unencrypted
        encrypted_password = conn.recv(2048)
        password = decrypt(encrypted_password).strip()
        if not password:
            conn.close()
            # throw an exception for invalid password
            raise Exception("Invalid password")

        with lock:
            # Check if username already exists in clients (already logged in)
            if username in clients:
                debug_print(f"User {username} is already logged in, rejecting duplicate connection", username)
                conn.send(encrypt("ERROR: User already logged in.\n"))
                conn.close()
                # Do NOT call remove() here as no entry was added to clients dict
                raise Exception("Duplicate connection")
                
            # Check if this is a registered user with incorrect password
            if username in credentials:
                if credentials[username] != password:
                    conn.send(encrypt("ERROR: Incorrect password.\n"))
                    conn.close()
                    # Do NOT call remove() here as no entry was added to clients dict
                    raise Exception("Invalid password")
            else:
                # New user, register them
                credentials[username] = password

            # Add user to active clients
            clients[username] = conn
            
            if username not in history:
                history[username] = []

        send_to_client(username, "Welcome to the chatroom, " + username + "!")
        broadcast("* " + username + " has joined the chat *", conn)
        print(username, "connected from", addr)

        # --- Main Communication Loop ---
        debug_print(f"Starting main communication loop for {username}", username)
        while True:
            try:
                # Use select with timeout to make the loop more responsive
                debug_print(f"Waiting for input from {username}", username)
                ready = select.select([conn], [], [], 1)
                if ready[0]:
                    encrypted_message = conn.recv(2048)
                    if not encrypted_message:
                        debug_print(f"Empty message from {username}, closing connection.", username)
                        break
                    
                    # Decrypt the message
                    message_str = decrypt(encrypted_message).strip()
                    if not message_str:
                        debug_print(f"Empty string from {username}, continuing", username)
                        continue
                    
                    debug_print(f"From {username}: {message_str}", username)
                    
                    # Process the message - either a command or a regular chat message
                    try:
                        # Command handling
                        if message_str.startswith('@'):
                            process_command(username, message_str, conn)
                        else:
                            # Regular message broadcasting
                            debug_print(f"Broadcasting regular message from {username}", username)
                            broadcast(username + ": " + message_str, conn)
                    except Exception as e:
                        debug_print(f"Error processing message from {username}: {e}", username)
                        traceback.print_exc()
                        send_to_client(username, f"Error processing your message: {str(e)}")
                        
            except ConnectionResetError:
                debug_print(f"Connection reset by {username}", username)
                break
            except Exception as e:
                debug_print(f"Exception with {username}: {e}", username)
                traceback.print_exc()
                break
                
    except Exception as ex:
        debug_print(f"Error with client {addr}: {ex}")
        traceback.print_exc()
    finally:
        with lock:
            debug_print(f"Cleaning up resources for {username}", username)
            # Only remove this exact connection from clients dict
            # to avoid affecting other connections with the same username
            if username and username in clients and clients[username] == conn:
                del clients[username]
                debug_print(f"Removed {username} from clients dict", username)
            
        # Only broadcast that the user left if this was an actual user session
        # that made it past authentication
        if username and username in clients.keys():
            broadcast(f"* {username} has left the chat *\n", conn)
        
        try:
            conn.close()
            debug_print(f"Closed socket for {username or 'unknown'}", username or "unknown")
        except:
            debug_print(f"Error closing socket for {username or 'unknown'}", username or "unknown")
        debug_print(f"Connection closed for {username or 'unknown'} from {addr}", username or "unknown")

# Command handler functions
def handle_quit(username, args, conn):
    """Handle @quit command"""
    send_to_client(username, "Goodbye!\n")
    return True  # Signal to break the main loop

def handle_names(username, args, conn):
    """Handle @names command"""
    with lock:
        names_list = ", ".join(clients.keys())
    send_to_client(username, "Online users: " + names_list + "\n")
    
def handle_history(username, args, conn):
    """Handle @history command"""
    if not args:
        send_to_client(username, "Usage: @history <number>\n")
        return
        
    try:
        N = int(args[0])
        # Get history with minimal lock time
        user_hist = []
        with lock:
            user_hist = history.get(username, [])[:]  # Make a copy
        
        # Process outside lock
        if not user_hist:
            send_to_client(username, "No chat history available.\n")
        else:
            # Filter out any previous history headers
            filtered_hist = [msg for msg in user_hist if not msg.startswith("--- Last")]
            
            # Create the header separately
            hist_header = "\n--- Last {} Messages ---\n".format(min(N, len(filtered_hist)))
            
            # Get the last N messages from filtered history
            hist_entries = filtered_hist[-N:]
            hist_msg = "\n".join(hist_entries)
            
            # Send header and history separately (header won't be stored in history)
            send_to_client(username, hist_header)
            send_to_client(username, hist_msg)
    except ValueError:
        send_to_client(username, "ERROR: Please provide a valid number.\n")

def handle_private_message(username, args, conn):
    """Handle private message (@user message)"""
    if not args or ' ' not in args[0]:
        send_to_client(username, "Usage: @username message\n")
        return
        
    target = args[0]
    msg_text = ' '.join(args[1:])
    
    # Check if target is in clients
    with lock:
        target_exists = target in clients
    
    if target_exists:
        send_to_client(target, "[DM from " + username + "]: " + msg_text + "\n")
        send_to_client(username, "[DM to " + target + "]: " + msg_text + "\n")
    else:
        send_to_client(username, "ERROR: User " + target + " not online.\n")

def handle_group_set(username, args, conn):
    """Handle @group set command"""
    if len(args) < 2:
        send_to_client(username, "Usage: @group set <group_name> <user1>,<user2>,...\n")
        return
    
    group_name = args[1]
    if len(args) < 3:
        send_to_client(username, "Usage: @group set <group_name> <user1>,<user2>,...\n")
        return
        
    members_str = args[2]  # The comma-separated list is a single argument
    members = [m.strip() for m in members_str.split(',') if m.strip()]
    members.append(username)
    
    # Check group and build member list with minimal lock time
    group_exists = False
    not_online = []
    with lock:
        group_exists = group_name in groups
        if not group_exists:
            not_online = [m for m in members if m not in clients]
    
    if group_exists:
        send_to_client(username, "ERROR: Group " + group_name + " already exists.\n")
    elif not_online:
        send_to_client(username, "ERROR: These users not online: " + ", ".join(not_online) + "\n")
    else:
        # Create the group with a separate lock
        with lock:
            groups[group_name] = set(members)
        send_to_client(username, "Group " + group_name + " created with members: " + 
                     ", ".join(members) + "\n")

def handle_group_send(username, args, conn):
    """Handle @group send command"""
    if len(args) < 3:
        send_to_client(username, "Usage: @group send <group_name> <message>\n")
        return
    
    group_name = args[1]
    group_msg = ' '.join(args[2:])  # Combine all remaining args as the message
    
    # Check group membership with minimal lock time
    group_exists = False
    is_member = False
    member_list = []
    with lock:
        group_exists = group_name in groups
        if group_exists:
            is_member = username in groups[group_name]
            if is_member:
                # Make a copy of the member list
                member_list = list(groups[group_name])
    
    if not group_exists:
        send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
    elif not is_member:
        send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
    else:
        full_msg = "[Group: " + group_name + "] " + username + ": " + group_msg + "\n"
        # Send to each member outside the lock
        for member in member_list:
            # Check if member is still connected
            with lock:
                member_connected = member in clients
            if member_connected:
                send_to_client(member, full_msg)

def handle_group_leave(username, args, conn):
    """Handle @group leave command"""
    if len(args) < 2:
        send_to_client(username, "Usage: @group leave <group_name>\n")
        return
    
    group_name = args[1]
    
    # Check group with minimal lock time
    group_exists = False
    is_member = False
    with lock:
        group_exists = group_name in groups
        if group_exists:
            is_member = username in groups[group_name]
            if is_member:
                groups[group_name].remove(username)
    
    if not group_exists:
        send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
    elif not is_member:
        send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
    else:
        send_to_client(username, "You left group " + group_name + ".\n")

def handle_group_delete(username, args, conn):
    """Handle @group delete command"""
    if len(args) < 2:
        send_to_client(username, "Usage: @group delete <group_name>\n")
        return
    
    group_name = args[1]
    
    # Check group with minimal lock time
    group_exists = False
    is_member = False
    with lock:
        group_exists = group_name in groups
        if group_exists:
            is_member = username in groups[group_name]
            if is_member:
                del groups[group_name]
    
    if not group_exists:
        send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
    elif not is_member:
        send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
    else:
        send_to_client(username, "Group " + group_name + " deleted.\n")

# Group command handler mapping
GROUP_COMMAND_HANDLERS = {
    "set": handle_group_set,
    "send": handle_group_send,
    "leave": handle_group_leave,
    "delete": handle_group_delete
}

def handle_group(username, args, conn):
    """Handle @group command"""
    if not args:
        send_to_client(username, "Usage: @group <set|send|leave|delete> ...\n")
        return
        
    subcmd = args[0]
    if subcmd in GROUP_COMMAND_HANDLERS:
        GROUP_COMMAND_HANDLERS[subcmd](username, args, conn)
    else:
        send_to_client(username, "ERROR: Unknown group command.\n")

# Main command handler mapping
COMMAND_HANDLERS = {
    "@quit": handle_quit,
    "@names": handle_names,
    "@history": handle_history,
    "@group": handle_group
}

def process_command(username, message_str, conn):
    """Process a command message"""
    debug_print(f"Processing command: {message_str}", username)
    
    # Handle special case for @group command with proper argument parsing
    if message_str.startswith('@group'):
        # Split only into main parts to preserve message spaces
        parts = message_str.split(' ', 3)  # Split into max 4 parts: @group, subcmd, group_name, [rest]
        
        if len(parts) < 2:
            send_to_client(username, "Usage: @group <set|send|leave|delete> ...\n")
            return False
        
        subcmd = parts[1]
        
        # Prepare args differently based on the subcommand
        if subcmd == "set" and len(parts) >= 4:
            # Format: @group set group_name user1,user2,...
            handle_group_set(username, ["set", parts[2], parts[3]], conn)
        elif subcmd == "send" and len(parts) >= 4:
            # Format: @group send group_name message
            handle_group_send(username, ["send", parts[2], parts[3]], conn)
        elif subcmd == "leave" and len(parts) >= 3:
            # Format: @group leave group_name
            handle_group_leave(username, ["leave", parts[2]], conn)
        elif subcmd == "delete" and len(parts) >= 3:
            # Format: @group delete group_name
            handle_group_delete(username, ["delete", parts[2]], conn)
        else:
            # Improper command format
            if subcmd == "set":
                send_to_client(username, "Usage: @group set <group_name> <user1>,<user2>,...\n")
            elif subcmd == "send":
                send_to_client(username, "Usage: @group send <group_name> <message>\n")
            elif subcmd == "leave":
                send_to_client(username, "Usage: @group leave <group_name>\n")
            elif subcmd == "delete":
                send_to_client(username, "Usage: @group delete <group_name>\n")
            else:
                send_to_client(username, "ERROR: Unknown group command.\n")
        return False
        
    # Parse the command for other commands
    parts = message_str.split()
    command = parts[0]
    args = parts[1:] if len(parts) > 1 else []
    
    if command == "@help":
        help_msg = "Available commands:\n" + \
                   "@quit - Quit the chat\n" + \
                   "@names - List online users\n" + \
                   "@history <number> - Show last N messages\n" + \
                   "@group set <group_name> <user1>,<user2>,... - Create a group\n" + \
                   "@group send <group_name> <message> - Send a message to a group\n" + \
                   "@group leave <group_name> - Leave a group\n" + \
                   "@group delete <group_name> - Delete a group\n" + \
                   "@help - Show this help message\n"
        send_to_client(username, help_msg)
        return False
    # Special case for private messages (@username message)
    elif command.startswith('@') and command != "@quit" and command != "@names" and \
       command != "@history" and not command.startswith('@group'):
        # This is a private message
        target = command[1:]  # Remove the @ symbol
        handle_private_message(username, [target] + args, conn)
        return False

    # Look up the command in our handlers dictionary
    if command in COMMAND_HANDLERS:
        return COMMAND_HANDLERS[command](username, args, conn)
    else:
        send_to_client(username, "ERROR: Unknown command.\n")
        return False

def keyboard_listener():
    """Thread function to listen for keyboard input to shut down the server"""
    global server_running
    print("Press 'q' or 'Q' to quit the server")
    
    if msvcrt_available():
        import msvcrt
        while server_running:
            if msvcrt.kbhit():
                key = msvcrt.getch().decode('utf-8', errors='ignore').lower()
                if key == 'q':
                    print("\nServer shutdown initiated by keyboard command...")
                    server_running = False
                    break
            time.sleep(0.1)
    else:
        # For non-Windows platforms, use a simpler approach
        try:
            while server_running:
                key = input()  # This will block until Enter is pressed
                if key.lower() == 'q':
                    print("\nServer shutdown initiated by keyboard command...")
                    server_running = False
                    break
                time.sleep(0.1)
        except EOFError:
            # This can happen when redirecting stdin/stdout
            pass

def broadcast_shutdown():
    """Send a shutdown message to all connected clients"""
    shutdown_msg = "SERVER SHUTTING DOWN. Goodbye!\n"
    debug_print("Broadcasting shutdown message")
    
    with lock:
        clients_copy = list(clients.items())
    
    for username, conn in clients_copy:
        try:
            send_to_client(username, shutdown_msg)
        except:
            debug_print(f"Failed to send shutdown message to {username}")

def close_all_connections():
    """Close all client connections"""
    debug_print("Closing all client connections")
    
    with lock:
        clients_copy = list(clients.items())
    
    for username, conn in clients_copy:
        try:
            debug_print(f"Closing connection for {username}")
            conn.close()
        except:
            debug_print(f"Error closing connection for {username}")
    
    # Also clear the online_users dictionary
    with lock:
        online_users.clear()
        debug_print("Cleared online users list")

def main():
    global server_running
    # Check for correct number of arguments
    if len(args) != 3:
        print("Usage: script IP_address port [--debug]")
        sys.exit()
    IP_address = str(args[1])
    Port = int(args[2])
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    debug_print("Server starting")
    
    # Start keyboard listener thread
    keyboard_thread = threading.Thread(target=keyboard_listener)
    keyboard_thread.daemon = True
    keyboard_thread.start()
    
    try:
        server.bind((IP_address, Port))
        server.listen(100)
        print("Enhanced Server started on", IP_address, "port", Port)
        
        debug_print("Server running, waiting for connections")
        
        # Set a timeout on accept() so we can check server_running flag
        server.settimeout(1.0)
        
        while server_running:
            try:
                conn, addr = server.accept()
                print(addr[0], "connected")
                start_new_thread(clientthread, (conn, addr))
            except socket.timeout:
                # This is expected due to the timeout we set
                continue
            except KeyboardInterrupt:
                print("\nShutting down server...")
                server_running = False
                break
            except Exception as e:
                debug_print(f"Error accepting connection: {e}")
                
        # Server shutdown procedures
        print("Performing graceful shutdown...")
        broadcast_shutdown()
        close_all_connections()
                
    except Exception as e:
        debug_print(f"Server error: {e}")
    finally:
        server.close()
        debug_print("Server shut down")
        # Small delay to allow debug messages to be printed
        time.sleep(0.5)

if __name__ == "__main__":
    main()
