import socket
import select
import sys
from _thread import start_new_thread
import threading
import time
import traceback

# Global data structures
credentials = {}   # username -> password
clients = {}       # username -> connection
groups = {}        # group_name -> set of usernames
history = {}       # username -> list of messages

lock = threading.Lock()

# Helper: send message to a specific user and log it in their history.
def send_to_client(username, message):
    try:
        if username in clients:
            clients[username].send(message.encode())
            # Add a small delay to prevent overwhelming the socket
            time.sleep(0.01)
    except Exception as e:
        print(f"Error sending to {username}: {e}")
        # Don't remove client here, let the main thread handle it
    
    # Append message to user's history (limit to 50 entries)
    with lock:
        if username in history:
            history[username].append(message)
            if len(history[username]) > 50:
                history[username] = history[username][-50:]
        else:
            history[username] = [message]

def broadcast(message, exclude_conn=None):
    with lock:
        for user, conn in list(clients.items()):  # Create a copy with list() to avoid dict changes during iteration
            if conn != exclude_conn:
                try:
                    conn.send(message.encode())
                    # Add a small delay to prevent overwhelming the socket
                    time.sleep(0.01)
                    
                    # Update history
                    if user in history:
                        history[user].append(message)
                        if len(history[user]) > 50:
                            history[user] = history[user][-50:]
                    else:
                        history[user] = [message]
                except Exception as e:
                    print(f"Error broadcasting to {user}: {e}")
                    # Close and remove failed connections
                    try:
                        conn.close()
                    except:
                        pass
                    remove(conn)

def remove(conn):
    with lock:
        removed_user = None
        for user, client_conn in list(clients.items()):
            if client_conn == conn:
                removed_user = user
                del clients[user]
                print(f"Removed user: {user}")
                break
        return removed_user

def clientthread(conn, addr):
    username = ""
    try:
        # --- Authentication Phase ---
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

        send_to_client(username, "Welcome to the chatroom, " + username + "!\n")
        broadcast("* " + username + " has joined the chat *\n", conn)
        print(username, "connected from", addr)

        # --- Main Communication Loop ---
        while True:
            try:
                # Use select with timeout to make the loop more responsive
                ready = select.select([conn], [], [], 1)
                if ready[0]:
                    message = conn.recv(2048)
                    if not message:
                        print(f"Empty message from {username}, closing connection.")
                        break
                    
                    message_str = message.decode().strip()
                    if not message_str:
                        continue
                    
                    print(f"From {username}: {message_str}")
                    
                    # Command handling
                    if message_str.startswith('@'):
                        # --- Handle different commands ---
                        if message_str == "@quit":
                            send_to_client(username, "Goodbye!\n")
                            break
                            
                        elif message_str == "@names":
                            with lock:
                                names_list = ", ".join(clients.keys())
                            send_to_client(username, "Online users: " + names_list + "\n")
                            continue  # Don't break, continue the loop
                            
                        elif message_str.startswith('@history'):
                            # Process history command
                            parts = message_str.split()
                            if len(parts) != 2:
                                send_to_client(username, "Usage: @history <number>\n")
                            else:
                                try:
                                    N = int(parts[1])
                                    user_hist = history.get(username, [])
                                    hist_msg = "\n--- Last {} Messages ---\n".format(min(N, len(user_hist)))
                                    hist_msg += "\n".join(user_hist[-N:])
                                    send_to_client(username, hist_msg + "\n")
                                except ValueError:
                                    send_to_client(username, "ERROR: Please provide a valid number.\n")
                            continue  # Continue the loop
                            
                        # Private message handling
                        elif message_str[1:].find(' ') != -1 and not message_str.startswith('@group'):
                            target, msg_text = message_str[1:].split(' ', 1)
                            with lock:
                                if target in clients:
                                    send_to_client(target, "[DM from " + username + "]: " + msg_text + "\n")
                                    send_to_client(username, "[DM to " + target + "]: " + msg_text + "\n")
                                else:
                                    send_to_client(username, "ERROR: User " + target + " not online.\n")
                            continue  # Continue the loop
                            
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
                                with lock:
                                    if group_name in groups:
                                        send_to_client(username, "ERROR: Group " + group_name + " already exists.\n")
                                    else:
                                        not_online = [m for m in members if m not in clients]
                                        if not_online:
                                            send_to_client(username, "ERROR: These users not online: " + ", ".join(not_online) + "\n")
                                        else:
                                            groups[group_name] = set(members)
                                            send_to_client(username, "Group " + group_name + " created with members: " +
                                                         ", ".join(groups[group_name]) + "\n")
                            elif subcmd == "send":
                                if len(parts) < 3 or ' ' not in parts[2]:
                                    send_to_client(username, "Usage: @group send <group_name> <message>\n")
                                    continue
                                group_name, group_msg = parts[2].split(' ', 1)
                                with lock:
                                    if group_name not in groups:
                                        send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
                                    elif username not in groups[group_name]:
                                        send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
                                    else:
                                        full_msg = "[Group: " + group_name + "] " + username + ": " + group_msg + "\n"
                                        for member in groups[group_name]:
                                            if member in clients:
                                                send_to_client(member, full_msg)
                            elif subcmd == "leave":
                                if len(parts) < 3:
                                    send_to_client(username, "Usage: @group leave <group_name>\n")
                                    continue
                                group_name = parts[2].strip()
                                with lock:
                                    if group_name not in groups:
                                        send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
                                    elif username not in groups[group_name]:
                                        send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
                                    else:
                                        groups[group_name].remove(username)
                                        send_to_client(username, "You left group " + group_name + ".\n")
                            elif subcmd == "delete":
                                if len(parts) < 3:
                                    send_to_client(username, "Usage: @group delete <group_name>\n")
                                    continue
                                group_name = parts[2].strip()
                                with lock:
                                    if group_name not in groups:
                                        send_to_client(username, "ERROR: Group " + group_name + " does not exist.\n")
                                    elif username not in groups[group_name]:
                                        send_to_client(username, "ERROR: You are not a member of group " + group_name + ".\n")
                                    else:
                                        del groups[group_name]
                                        send_to_client(username, "Group " + group_name + " deleted.\n")
                            else:
                                send_to_client(username, "ERROR: Unknown group command.\n")
                            continue  # Continue the loop
                            
                        else:
                            send_to_client(username, "ERROR: Unknown command.\n")
                            continue  # Continue the loop
                            
                    else:
                        # Regular message broadcasting
                        broadcast(username + ": " + message_str + "\n", conn)
                        
            except ConnectionResetError:
                print(f"Connection reset by {username}")
                break
            except Exception as e:
                print(f"Exception with {username}: {e}")
                traceback.print_exc()
                break
                
    except Exception as ex:
        print(f"Error with client {addr}: {ex}")
        traceback.print_exc()
    finally:
        with lock:
            if username in clients:
                del clients[username]
        broadcast(f"* {username} has left the chat *\n", conn)
        try:
            conn.close()
        except:
            pass
        print(f"Connection closed for {username} from {addr}")

def main():
    if len(sys.argv) != 3:
        print("Usage: script IP_address port")
        sys.exit()
    IP_address = str(sys.argv[1])
    Port = int(sys.argv[2])
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((IP_address, Port))
        server.listen(100)
        print("Enhanced Server started on", IP_address, "port", Port)
        
        while True:
            try:
                conn, addr = server.accept()
                print(addr[0], "connected")
                start_new_thread(clientthread, (conn, addr))
            except KeyboardInterrupt:
                print("\nShutting down server...")
                break
            except Exception as e:
                print(f"Error accepting connection: {e}")
                
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server.close()
        print("Server shut down")

if __name__ == "__main__":
    main()