import socket
import select
import sys
from _thread import start_new_thread
import threading

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
    except:
        pass
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
        for user, conn in clients.items():
            if conn != exclude_conn:
                try:
                    conn.send(message.encode())
                    history[user].append(message)
                    if len(history[user]) > 50:
                        history[user] = history[user][-50:]
                except:
                    conn.close()
                    remove(conn)

def remove(conn):
    with lock:
        for user, client in list(clients.items()):
            if client == conn:
                del clients[user]
                break

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
                message = conn.recv(2048)
                if not message:
                    break
                message = message.decode().strip()
                if not message:
                    continue

                if message.startswith('@'):
                    if message == "@quit":
                        send_to_client(username, "Goodbye!\n")
                        break
                    elif message == "@names":
                        with lock:
                            names_list = ", ".join(clients.keys())
                        send_to_client(username, "Online users: " + names_list + "\n")
                    elif message.startswith('@history'):
                        # Expected format: @history <N>
                        parts = message.split()
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
                    # Private message: @target <message>
                    elif message[1:].find(' ') != -1 and not message.startswith('@group'):
                        target, msg_text = message[1:].split(' ', 1)
                        with lock:
                            if target in clients:
                                send_to_client(target, "[DM from " + username + "]: " + msg_text + "\n")
                                send_to_client(username, "[DM to " + target + "]: " + msg_text + "\n")
                            else:
                                send_to_client(username, "ERROR: User " + target + " not online.\n")
                    elif message.startswith('@group'):
                        parts = message.split(' ', 2)
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
                    else:
                        send_to_client(username, "ERROR: Unknown command.\n")
                else:
                    broadcast(username + ": " + message + "\n", conn)
            except Exception as e:
                print("Exception:", e)
                break
    except Exception as ex:
        print("Error with client", addr, ":", ex)
    finally:
        with lock:
            if username in clients:
                del clients[username]
        broadcast("* " + username + " has left the chat *\n", conn)
        conn.close()

def main():
    if len(sys.argv) != 3:
        print("Usage: script IP_address port")
        sys.exit()
    IP_address = str(sys.argv[1])
    Port = int(sys.argv[2])
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((IP_address, Port))
    server.listen(100)
    print("Enhanced Server started on", IP_address, "port", Port)
    
    while True:
        conn, addr = server.accept()
        print(addr[0], "connected")
        start_new_thread(clientthread, (conn, addr))
    
    server.close()

if __name__ == "__main__":
    main()