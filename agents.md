# PyMeow: AI Agent Guide

## Repository Overview

PyMeow is a Python asyncio implementation of the WhatsApp Web multidevice API, based on the Go library "whatsmeow".
This library allows developers to interact with WhatsApp programmatically to send and receive WhatsApp messages.

## Project Structure

```
pymeow/
├── pymeow/                 # Main package directory
│   ├── client.py           # Core client implementation
│   ├── qrchan.py           # QR code handling for authentication
│   ├── socket/             # WebSocket implementation
│   ├── store/              # Device and session storage
│   │   └── sqlstore/       # SQL-based storage implementation
│   ├── datatypes/          # Data structures and types
│   │   └── events.py       # Event handling (messages, connections, etc.)
│   └── tests/              # Test suite
├── client_test.py          # Example client implementation
└── pyproject.toml          # Project configuration
```

## Key Concepts

### Client

The `Client` class is the main entry point for interacting with WhatsApp. It handles:
- Connection management
- Authentication
- Message sending and receiving
- Event handling

### Authentication

PyMeow supports authentication via QR code scanning, similar to WhatsApp Web:
1. Generate a QR code using the client
2. Scan the QR code with the WhatsApp mobile app
3. Once authenticated, the session is stored for future use

### Event Handling

The library uses an event-based system to handle various WhatsApp events:
- `Message`: Incoming messages
- `QR`: QR code events for authentication
- `Connected`: Connection established
- `Disconnected`: Connection lost

### Storage

Device information and session data are stored using tortoise orm and is intended to support sqlite (default) and postgres.
Tests use an sqlite in memory db.

## Common Tasks

### Setting Up a Client

```python
from pymeow.client import Client
from pymeow.store.sqlstore.container import Container

# Create database container
container = await Container("sqlite:///device_storage.db").ainit()

# Get or create device store
device_store = await container.get_first_device()
if device_store is None:
    device_store = await container.new_device("user@example.com")

# Create WhatsApp client
client = await Client(device_store).ainit()
```

### Handling Events

```python
async def event_handler(event):
    if isinstance(event, Message):
        # Handle incoming messages
        message_text = event.message.get_conversation()
        print(f"Received message: {message_text}")
    elif isinstance(event, Connected):
        print("Connected to WhatsApp")
    # Add more event handlers as needed

# Register the event handler
client.add_event_handler(event_handler)
```

### Authentication with QR Code

```python
from pymeow.qrchan import get_qr_channel

# Get QR channel for authentication
qr_channel = await get_qr_channel(client)

# Connect to WhatsApp
await client.connect()

# Wait for QR events or successful authentication
async for qr_event in qr_channel:
    if qr_event.event == "code":
        # Display QR code for scanning
        print(f"QR Code: {qr_event.code}")
    elif qr_event.event == "success":
        print("Successfully authenticated!")
        break
```

### Sending Messages

```python
from pymeow.datatypes.jid import JID

# Create a JID for the recipient
recipient = JID.from_string("1234567890@s.whatsapp.net")

# Send a text message
await client.send_message(recipient, "Hello from PyMeow!")
```

## Best Practices

1. **Error Handling**: Always implement proper error handling, especially for network operations.
2. **Resource Management**: Use async context managers or try/finally blocks to ensure resources are properly closed.
3. **Rate Limiting**: Be mindful of WhatsApp's rate limits to avoid being blocked.
4. **Privacy**: Respect user privacy and comply with relevant regulations when processing messages.
5. **Graceful Shutdown**: Implement proper shutdown procedures to disconnect cleanly.

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Ensure the QR code is scanned within the timeout period
   - Check that the WhatsApp mobile app is up to date

2. **Connection Issues**:
   - Verify network connectivity
   - Check if the WhatsApp service is experiencing outages

3. **Message Sending Failures**:
   - Confirm the recipient JID is correctly formatted
   - Ensure the client is properly authenticated and connected

## Development Guidelines

### Testing

The project uses pytest for testing. Run tests with:

```bash
pytest pymeow/tests
```
Also run ruff and mypy:
```bash
ruff check
mypy .
ruff format --check
```
### Code Style

The project follows Python best practices:
- Type hints are used throughout the codebase
- Black is used for code formatting
- Ruff is used for linting

### Contributing

When contributing to PyMeow:
1. Write tests for new features
2. Ensure code passes all linting checks
3. Document new functionality
4. Follow the existing code style

## Project Setup

### Installing uv

[uv](https://github.com/astral-sh/uv) is a Python package installer and resolver that's used in this project for dependency management. To install uv:

```bash
# Install with pip
pip install uv
```

### Python Version

PyMeow requires Python 3.13.3. You can use uv to install the correct Python version:

```bash
# Install Python 3.13.3
uv python install 3.13.3
```

### Setting Up the Development Environment

1. Clone the repository:

2. Create a virtual environment with uv:
   ```bash
   uv venv
   ```

3. Activate the virtual environment:
   ```bash
   # On Windows
   .venv\Scripts\activate

   # On macOS/Linux
   source .venv/bin/activate
   ```

4. Install dependencies using uv:
   ```bash
   # Install all dependencies
   uv sync
   ```

### Managing Dependencies

- Update dependencies to their latest compatible versions:
  ```bash
  uv sync --upgrade
  ```

- Add a new dependency:
  ```bash
  uv add package_name
  ```

- Add a development dependency:
  ```bash
  uv add --dev package_name
  ```

## Resources

- [WhatsApp Web API Documentation](https://developers.facebook.com/docs/whatsapp/)
- [Original whatsmeow Go library](https://github.com/tulir/whatsmeow)
- [Signal Protocol Documentation](https://signal.org/docs/)

## Examples

For complete examples, refer to the `client_test.py` file in the repository, which demonstrates a fully functional WhatsApp client implementation.

## WhatsApp Agent Concepts

In addition to this guide for AI agents working with the codebase, it's important to understand that WhatsApp itself has several agent-related concepts:

### JID Agents

In WhatsApp's identification system, a JID (Jabber ID) can include an "agent" component. This is part of the AD-JID structure (user, agent, and device).

A complete WhatsApp JID may have the following format:
```
user.agent:device@server
```

For example:
```
1234567890.2:1@s.whatsapp.net
```

The `JID` class in PyMeow handles these agent values with properties like `raw_agent` and methods like `actual_agent()`.

### User Agents

The library uses User-Agent strings for HTTP requests to identify the client to WhatsApp servers. The `Client` class includes a `user_agent` property used in HTTP requests.

### Bot Capabilities

WhatsApp bots can have various capabilities, including `AGENTIC_PLANNING` that allows bots to perform planning actions.

For more details on these WhatsApp-specific agent concepts, refer to the relevant files in the codebase:
- `pymeow/datatypes/jid.py`: JID implementation with agent handling
- `pymeow/store/clientpayload.py`: User agent configuration
- `pymeow/client.py`: Client configuration including user agent
