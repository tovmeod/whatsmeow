# Message History Sync Implementation

This document provides an overview of the message history synchronization feature in PyMeow, which allows you to sync and manage message history from the servers.

## Table of Contents
- [Overview](#overview)
- [Sync Types](#sync-types)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Implementation Details](#implementation-details)

## Overview

Message history sync enables your application to retrieve and maintain a local copy of message history from the servers. This is particularly useful for:

- Displaying message history when the client first connects
- Keeping messages in sync across multiple devices
- Implementing search and filtering of past messages
- Restoring message history after reinstallation

## Sync Types

PyMeow supports different types of sync operations through the `HistorySyncType` enum:

- `FULL`: Full message history sync (may be rate-limited)
- `RECENT`: Only sync recent messages (default)
- `PUSH_NAME`: Sync push name changes
- `NON_BLOCKING`: Non-blocking sync operation
- `ON_DEMAND`: On-demand sync when explicitly requested

## Usage Examples

### Basic Sync on Connection

```python
from py import Client, HistorySyncType


async def main():
    client = Client()
    # Connect with default sync (RECENT messages)
    await client.connect()

    # Or specify sync type
    # await client.connect(sync_type=HistorySyncType.FULL)

    # Your application code here

    await client.disconnect()
```

### Manual Sync

```python
# Sync messages for all chats
sync_result = await client.sync_messages(
    sync_type=HistorySyncType.RECENT,
    count=100  # Number of messages to sync
)
print(f"Sync result: {sync_result}")

# Sync messages for a specific chat
sync_result = await client.sync_messages(
    chat_jid='1234567890@s.whatsapp.net',
    count=50
)
```

### Working with Conversations

```python
# Get list of conversations (chats with latest messages)
conversations = await client.get_conversations(limit=20)
for conv in conversations:
    print(f"Chat with {conv.get('name')}: {conv.get('last_message', {}).get('content')}")

# Get detailed info about a specific conversation
chat_info = await client.get_conversation_info('1234567890@s.whatsapp.net')
if chat_info:
    print(f"Chat name: {chat_info.get('name')}")
    print(f"Last message: {chat_info.get('last_message', {}).get('content')}")
```

## API Reference

### Client Methods

#### `sync_messages`

```python
async def sync_messages(
    self,
    sync_type: HistorySyncType = HistorySyncType.FULL,
    chat_jid: Optional[str] = None,
    count: int = 100,
    cursor: Optional[str] = None
) -> Dict[str, Any]
```

Synchronize message history from the server.

**Parameters:**
- `sync_type`: Type of sync to perform (default: `HistorySyncType.FULL`)
- `chat_jid`: Optional chat JID to sync messages for (if None, syncs all chats)
- `count`: Number of messages to sync (default: 100)
- `cursor`: Pagination cursor from previous sync

**Returns:**
Dictionary containing sync results including status and cursor for pagination

#### `get_conversations`

```python
async def get_conversations(
    self,
    limit: int = 50,
    before: Optional[float] = None
) -> List[Dict[str, Any]]
```

Get list of conversations with their latest messages.

**Parameters:**
- `limit`: Maximum number of conversations to return (default: 50)
- `before`: Only return conversations before this timestamp (for pagination)

**Returns:**
List of conversation dictionaries with metadata

#### `get_conversation_info`

```python
async def get_conversation_info(self, chat_jid: str) -> Optional[Dict[str, Any]]
```

Get detailed information about a conversation.

**Parameters:**
- `chat_jid`: The JID of the chat to get info for

**Returns:**
Dictionary with conversation details or None if not found

## Implementation Details

### Database Schema

The message history is stored in an SQLite database with the following tables:

1. `messages` - Stores message content and metadata
2. `conversations` - Tracks conversation metadata
3. `sync_state` - Tracks synchronization state for different sync types
4. `conversation_info` - Stores additional conversation information

### Sync Process

1. The client sends a sync request to the server
2. The server responds with a chunk of message history
3. The client processes and stores the messages in the local database
4. The client updates the sync state with the latest cursor and timestamp
5. If there are more messages, the client requests the next chunk using the cursor

### Error Handling

- Network errors are automatically retried with exponential backoff
- Invalid or malformed messages are logged and skipped
- Sync state is preserved even if the sync is interrupted

## Best Practices

1. **Rate Limiting**: Be mindful of rate limits when performing frequent syncs
2. **Incremental Sync**: Use the `cursor` parameter to implement incremental syncs
3. **Error Handling**: Always handle potential errors when calling sync methods
4. **Background Sync**: Consider performing large syncs in the background
5. **Storage Management**: Implement cleanup of old messages if storage is a concern
