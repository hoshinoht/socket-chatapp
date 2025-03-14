import socket
import select
import sys
import os
import time

if len(sys.argv) != 3:
    print("Usage: script IP_address port")
    sys.exit()
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server.connect((IP_address, Port))
except ConnectionRefusedError:
    print(f"Unable to connect to server at {IP_address}:{Port}")
    sys.exit()
except Exception as e:
    print(f"Connection error: {e}")
    sys.exit()

# --- Authentication Sequence ---
try:
    sys.stdout.write(server.recv(2048).decode())
    sys.stdout.flush()
    username = input()  # Use input() instead of sys.stdin.readline() for better cross-platform support
    server.send(username.encode())

    sys.stdout.write(server.recv(2048).decode())
    sys.stdout.flush()
    password = input()
    server.send(password.encode())

    response = server.recv(2048).decode()
    if response.startswith("ERROR"):
        print(response)
        server.close()
        sys.exit()
    else:
        print(response)
except Exception as e:
    print(f"Error during authentication: {e}")
    server.close()
    sys.exit()

# --- Main Chat Loop ---
try:
    while True:
        # Windows compatibility for select
        if os.name == 'nt':  # Windows
            # Check for server messages
            readable, _, _ = select.select([server], [], [], 0.1)
            if server in readable:
                message = server.recv(2048).decode()
                if not message:
                    print("Connection closed by server")
                    break
                print(message)
            
            # Check for user input (non-blocking)
            if msvcrt_available():
                import msvcrt
                if msvcrt.kbhit():
                    message = input()
                    server.send(message.encode())
            else:
                # Fallback for Windows without msvcrt
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    message = input()
                    server.send(message.encode())
                time.sleep(0.1)
        else:  # Unix/Linux/Mac
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
                    message = input()
                    server.send(message.encode())
except KeyboardInterrupt:
    print("Disconnecting from server...")
except Exception as e:
    print(f"Error in communication: {e}")
finally:
    server.close()

# Helper function to check if msvcrt is available
def msvcrt_available():
    try:
        import msvcrt
        return True
    except ImportError:
        return False
