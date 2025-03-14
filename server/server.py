import socket
import select
import sys
from _thread import start_new_thread
import threading
import time
import traceback

# Enable debugging
DEBUG = True

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
        caller = traceback.extract_stack()[-2]
        debug_print(f"Attempting to acquire lock at {caller.filename}:{caller.lineno}")
        result = self._lock.acquire(blocking, timeout)
        if result:
            self.holder = threading.get_ident()
            self.acquire_time = time.time()
            debug_print(f"Lock acquired by thread {self.holder}")
        return result
        
    def release(self):
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
            
            # Send message in chunks to prevent buffer issues
            try:
                debug_print(f"Using sendall to {username}", username)
                clients[username].sendall(message.encode())
                debug_print(f"sendall successful to {username}", username)
            except Exception as sendall_error:
                debug_print(f"sendall failed, using regular send: {sendall_error}", username)
                # Fall back to regular send if sendall fails
                clients[username].send(message.encode())
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
                conn.send(message.encode())
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
        conn.send("Username: ".encode())
        username = conn.recv(2048).decode().strip()
        if not username:
            conn.close()
            return
        conn.send("Password: ".encode())
        password = conn.recv(2048).decode().strip()
        if not password:
            conn.close()
            return

        with lock:
            if username in credentials:
                if credentials[username] != password:
                    conn.send("ERROR: Incorrect password.\n".encode())
                    conn.close()
                    return
            else:
                credentials[username] = password

            if username in clients:
                conn.send("ERROR: User already logged in.\n".encode())
                conn.close()
                return
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
                    message = conn.recv(2048)
                    if not message:
                        debug_print(f"Empty message from {username}, closing connection.", username)
                        break
                    
                    message_str = message.decode().strip()
                    if not message_str:
                        debug_print(f"Empty string from {username}, continuing", username)
                        continue
                    
                    debug_print(f"From {username}: {message_str}", username)
                    
                    # Process the message - either a command or a regular chat message
                    try:
                        # Command handling
                        if message_str.startswith('@'):
                            debug_print(f"Processing command: {message_str}", username)
                            
                            # --- Handle different commands ---
                            if message_str == "@quit":
                                send_to_client(username, "Goodbye!\n")
                                break
                                
                            elif message_str == "@names":
                                # Get user list with minimal lock time
                                names_list = ""
                                with lock:
                                    names_list = ", ".join(clients.keys())
                                # Send response outside lock
                                send_to_client(username, "Online users: " + names_list + "\n")
                                continue
                                
                            elif message_str.startswith('@history'):
                                # Process history command
                                parts = message_str.split()
                                if len(parts) != 2:
                                    send_to_client(username, "Usage: @history <number>\n")
                                else:
                                    try:
                                        N = int(parts[1])
                                        # Get history with minimal lock time
                                        user_hist = []
                                        with lock:
                                            user_hist = history.get(username, [])[:]  # Make a copy
                                        
                                        # Process outside lock
                                        hist_msg = "\n--- Last {} Messages ---\n".format(min(N, len(user_hist)))
                                        hist_msg += "\n".join(user_hist[-N:])
                                        send_to_client(username, hist_msg + "\n")
                                    except ValueError:
                                        send_to_client(username, "ERROR: Please provide a valid number.\n")
                                continue
                                
                            # Private message handling
                            elif message_str[1:].find(' ') != -1 and not message_str.startswith('@group'):
                                target, msg_text = message_str[1:].split(' ', 1)
                                
                                # Fixed: Moving the lock to a smaller scope
                                target_exists = False
                                with lock:
                                    target_exists = target in clients
                                
                                if target_exists:
                                    send_to_client(target, "[DM from " + username + "]: " + msg_text + "\n")
                                    send_to_client(username, "[DM to " + target + "]: " + msg_text + "\n")
                                else:
                                    send_to_client(username, "ERROR: User " + target + " not online.\n")
                                continue
                                
                            # Group commands
                            elif message_str.startswith('@group'):
                                # Process group commands (set, send, leave, delete)
                                parts = message_str.split(' ', 2)
                                if len(parts) < 2:
                                    send_to_client(username, "ERROR: Invalid group command.\n")
                                    continue
                                    
                                subcmd = parts[1]
                                if subcmd == "set":
                                    if len(parts) < 3 or ' ' not in parts[2]:
                                        send_to_client(username, "Usage: @group set <group_name> <user1>,<user2>,...\n")
                                        continue
                                    
                                    group_name, members_str = parts[2].split(' ', 1)
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
                                    
                                elif subcmd == "send":
                                    if len(parts) < 3 or ' ' not in parts[2]:
                                        send_to_client(username, "Usage: @group send <group_name> <message>\n")
                                        continue
                                    
                                    group_name, group_msg = parts[2].split(' ', 1)
                                    
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
                                            member_connected = False
                                            with lock:
                                                member_connected = member in clients
                                            if member_connected:
                                                send_to_client(member, full_msg)
                                    
                                elif subcmd == "leave":
                                    if len(parts) < 3:
                                        send_to_client(username, "Usage: @group leave <group_name>\n")
                                        continue
                                    
                                    group_name = parts[2].strip()
                                    
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
                                    
                                elif subcmd == "delete":
                                    if len(parts) < 3:
                                        send_to_client(username, "Usage: @group delete <group_name>\n")
                                        continue
                                    
                                    group_name = parts[2].strip()
                                    
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
                                else:
                                    send_to_client(username, "ERROR: Unknown group command.\n")
                                continue
                                
                            else:
                                send_to_client(username, "ERROR: Unknown command.\n")
                                continue
                                
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
            if username in clients:
                del clients[username]
                debug_print(f"Removed {username} from clients dict", username)
        broadcast(f"* {username} has left the chat *\n", conn)
        try:
            conn.close()
            debug_print(f"Closed socket for {username}", username)
        except:
            debug_print(f"Error closing socket for {username}", username)
        debug_print(f"Connection closed for {username} from {addr}", username)

def main():
    if len(sys.argv) != 3:
        print("Usage: script IP_address port")
        sys.exit()
    IP_address = str(sys.argv[1])
    Port = int(sys.argv[2])
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    debug_print("Server starting")
    
    try:
        server.bind((IP_address, Port))
        server.listen(100)
        print("Enhanced Server started on", IP_address, "port", Port)
        
        debug_print("Server running, waiting for connections")
        
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
        debug_print("Server shut down")

if __name__ == "__main__":
    main()