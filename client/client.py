import socket
import select
import sys

if len(sys.argv) != 3:
    print("Usage: script IP_address port")
    sys.exit()
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((IP_address, Port))

# --- Authentication Sequence ---
sys.stdout.write(server.recv(2048).decode())
sys.stdout.flush()
username = sys.stdin.readline()
server.send(username.encode())

sys.stdout.write(server.recv(2048).decode())
sys.stdout.flush()
password = sys.stdin.readline()
server.send(password.encode())

response = server.recv(2048).decode()
if response.startswith("ERROR"):
    print(response)
    server.close()
    sys.exit()
else:
    print(response)

# --- Main Chat Loop ---
while True:
    sockets_list = [sys.stdin, server]
    read_sockets, _, _ = select.select(sockets_list, [], [])
    for sock in read_sockets:
        if sock == server:
            message = sock.recv(2048).decode()
            if not message:
                print("Connection closed by server")
                sys.exit()
            print(message)
        else:
            message = sys.stdin.readline()
            server.send(message.encode())
server.close()
