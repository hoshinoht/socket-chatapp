# Socket Chat Application

## Overview

The Socket Chat Application is a secure, real-time chat system that supports private messaging, group chats, and user authentication. It uses AES encryption (via the `cryptography` library) to ensure secure communication between clients and the server.

## Features

- **User Authentication**: Users must log in with a username and password. New users are automatically registered.
- **Private Messaging**: Send direct messages to specific users using `@username <message>`.
- **Group Chats**:
  - Create groups with `@group set <GroupName> <User1,User2,...>`.
  - Send messages to groups with `@group send <GroupName> <Message>`.
  - Leave groups with `@group leave <GroupName>`.
  - Delete groups with `@group delete <GroupName>`.
- **Chat History**: View the last `n` messages in your chat history using `@history <number>`.
- **User List**: List all currently connected users with `@names`.
- **Server Commands**: The server can be gracefully shut down using a keyboard command (`q` or `Q`).
- **Encryption**: All messages are encrypted using AES encryption to ensure privacy and security.
- **Cross-Platform Support**: The application runs on Windows, macOS, and Linux.

## Setup

### Dependencies

Before running the application, install the required dependencies:

```bash
pip install cryptography
```

### Project Structure

- **`server/server.py`**: The main server script that handles user connections, authentication, and message routing.
- **`client/client.py`**: The client application for users to connect to the server and participate in chats.
- **`utils/cipher.py`**: Provides encryption and decryption utilities using AES encryption.
- **`tests/`**: Contains unit and integration tests for the application.

## How to Run

1. **Start the server**:
   ```bash
   python server/server.py <IP_address> <port>
   ```
   Example:
   ```bash
   python server/server.py 127.0.0.1 9999
   ```

2. **Run one or more client instances**:
   ```bash
   python client/client.py <IP_address> <port>
   ```
   Example:
   ```bash
   python client/client.py 127.0.0.1 9999
   ```

3. **Enable debug mode (optional)**:
   Add `--debug` to the command to enable detailed logging for debugging purposes.

## Available Commands

### General Commands
- `@names` - List all connected users.
- `@history <number>` - View the last `n` messages in your chat history.
- `@quit` - Disconnect from the server.
- `@help` - Display a list of available commands.

### Private Messaging
- `@username <message>` - Send a private message to a specific user.

### Group Commands
- `@group set <GroupName> <User1,User2,...>` - Create a group with specified users.
- `@group send <GroupName> <Message>` - Send a message to a group.
- `@group leave <GroupName>` - Leave a group.
- `@group delete <GroupName>` - Delete a group.

## Security

This application uses AES encryption provided by the Fernet implementation from the `cryptography` library to secure all communications between clients and the server. All messages are encrypted before being sent and decrypted upon receipt.

## Testing

Run the test suite to ensure the application is functioning correctly:

```bash
python run_tests.py
```

The tests include:
- Unit tests for encryption and decryption (`tests/test_cipher.py`).
- Integration tests for client-server communication (`tests/test_integration.py`).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
