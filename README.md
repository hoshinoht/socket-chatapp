# websocket-chatapp

## Setup

### Dependencies
Before running the application, install the required dependencies:

```bash
pip install cryptography
```

## How to Run

1. Start the server:
   ```bash
   python server/server.py <IP_address> <port>
   ```

2. Run one or more client instances:
   ```bash
   python client/client.py <IP_address> <port>
   ```

## Available Commands

- `@names` - List all connected users
- `@group set <GroupName> <User1,User2,...>` - Create a group with specified users
- `@group send <GroupName> <Message>` - Send a message to a group
- `@history <number>` - View last n messages in your history
- `@quit` - Disconnect from the server

## Security

This application uses AES encryption provided by the Fernet implementation from the cryptography library to secure all communications between clients and the server.
