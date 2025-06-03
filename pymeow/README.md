# pymeow

[![PyPI](https://img.shields.io/pypi/v/pymeow)](https://pypi.org/project/pymeow/)
[![Python Version](https://img.shields.io/pypi/pyversions/pymeow)](https://pypi.org/project/pymeow/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A Python implementation of the Web multidevice API, compatible with the [whatsmeow](https://github.com/tulir/whatsmeow) Go library's protocol implementation.

> **Note**: This is a work in progress. Not all features are implemented yet.

## Features

- Full async/await support using asyncio
- Type hints throughout the codebase
- Event-based architecture
- Noise protocol encryption for secure communication
- Persistent authentication state
- Support for core features:
  - Secure WebSocket communication
  - Message encryption/decryption
  - Authentication and session management
  - Event handling
  - Message reactions (emojis)
  - And more...

## Implementation Status

| Feature | Status |
|---------|--------|
| WebSocket Connection | ✅ Implemented |
| Noise Protocol | ✅ Implemented |
| Authentication | ✅ Basic Implementation |
| Message Sending | 🚧 In Progress |
| Message Receiving | 🚧 In Progress |
| Media Support | ❌ Not Started |
| Group Management | ✅ Implemented |

## Installation

```bash
uv pip install pymeow
```

## Message Reactions

PyMeow supports sending and receiving message reactions. Here's how to use them:

### Sending a Reaction

```python
# Send a reaction to a message
reaction = await client.send_reaction(
    message_id="3EB0ABCD1234",  # The ID of the message to react to
    chat_jid="1234567890@s.whatsapp.net",  # The chat JID
    emoji="👍"  # The emoji to react with (empty string to remove reaction)
)
print(f"Reaction sent: {reaction}")
```

### Getting Reactions for a Message

```python
# Get all reactions for a message
reactions = await client.get_message_reactions("3EB0ABCD1234")
for reaction in reactions:
    print(f"{reaction['sender_jid']} reacted with {reaction['emoji']}")

# Get a summary of reactions
summary = await client.get_reaction_summary("3EB0ABCD1234")
for emoji, data in summary.items():
    print(f"{emoji}: {data['count']} reactions")
```

### Handling Reaction Events

You can listen for reaction events using the event system:

```python
@client.on('reaction')
async def handle_reaction(reaction):
    print(f"New reaction: {reaction}")
    # reaction contains: message_id, sender_jid, emoji, timestamp

# Start the client to receive events
await client.connect()
```

## Quick Start

### Basic Usage

```python
import asyncio
import logging
from pymeow import Client, AuthState

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

async def main():
    # Initialize with authentication state
    auth = AuthState()
    client = Client(auth_state=auth)

    # Register event handlers
    @client.on('connected')
    async def on_connected():
        print("✅ Connected")

    @client.on('authenticated')
    async def on_authenticated():
        print("🔑 Successfully authenticated")

    @client.on('qr')
    async def on_qr(qr_data):
        print("🔍 Scan the QR code to log in:")
        print(qr_data)  # In a real app, you'd render this as a QR code

    @client.on('message')
    async def on_message(message):
        print(f"📨 New message from {message.sender_id}: {message.content}")

    # Connect and authenticate
    try:
        await client.connect()

        # Keep the connection alive
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Disconnecting...")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Message Queue and Delivery Tracking

Pymeow includes a robust message queue system with delivery tracking. Here's how to use it:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    # Delivery receipt handler
    async def on_delivery(receipt):
        print(f"✅ Message delivered: {receipt['message_ids']}")

        # Mark message as read when delivered
        await client.mark_messages_read(receipt['message_ids'])

    # Read receipt handler
    async def on_read(receipt):
        print(f"👀 Message read by recipient: {receipt['message_ids']}")

    # Add handlers
    client.add_delivery_handler(on_delivery)
    client.add_read_receipt_handler(on_read)

    try:
        # Connect and authenticate...
        await client.connect()

        # Send a message with delivery tracking
        receipt = await client.send_message(
            to_jid="1234567890@s.whatsapp.net",
            content="Hello, World!",
            message_type="text"
        )

        print(f"📤 Message sent, waiting for delivery...")

        # Keep the connection alive
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Disconnecting...")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Contact Sharing

Pymeow supports sending contact information using vCards or simple phone numbers:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    try:
        # Connect and authenticate...
        await client.connect()

        # Send a single contact with a phone number
        await client.send_contact(
            to="1234567890@s.whatsapp.net",
            contact_jid="contact@whatsapp.net",
            name="John Doe",
            phone_number="1234567890"
        )

        # Send multiple contacts at once
        contacts = [
            {"name": "John Doe", "phone_number": "1234567890"},
            {"name": "Jane Smith", "phone_number": "0987654321"}
        ]
        await client.send_contacts(
            to="1234567890@s.whatsapp.net",
            contacts=contacts
        )

        # Keep the connection alive to process messages
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Disconnecting...")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Rate Limiting

Pymeow includes built-in rate limiting to help prevent being blocked by the servers:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    # Configure rate limits (optional, defaults are sensible)
    client.set_rate_limits(
        global_rate=1.0,           # 1 message per second globally
        global_capacity=5,         # Allow bursts of up to 5 messages
        per_recipient_rate=0.5,    # 1 message every 2 seconds per recipient
        per_recipient_capacity=10  # Allow bursts of up to 10 messages per recipient
    )

    # Handle rate limit events
    @client.on('rate_limit')
    async def on_rate_limit(event):
        print(f"⚠️  Rate limit hit: {event['recipient_jid']} - {event['error']}")
        print(f"Waiting before retrying...")

    try:
        # Connect and authenticate...
        await client.connect()

        # Send messages - rate limiting is handled automatically
        print("Sending multiple messages with rate limiting...")
        recipients = [
            "1234567890@s.whatsapp.net",
            "2345678901@s.whatsapp.net",
            "3456789012@s.whatsapp.net"
        ]

        for i, recipient in enumerate(recipients, 1):
            print(f"Sending message {i} to {recipient}")
            await client.send_message(
                to_jid=recipient,
                content=f"Hello {i}! This is a test message with rate limiting."
            )

        # Check current rate limit status
        status = client.get_rate_limit_status()
        print(f"\nRate limit status: {status}")

        # Keep the connection alive to process messages
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Disconnecting...")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Group Management

### Create a Group

```python
# Create a new group
group_info = await client.create_group(
    subject="My New Group",
    participants=["1234567890@s.whatsapp.net", "0987654321@s.whatsapp.net"]
)
print(f"Created group {group_info['id']} with subject {group_info['subject']}")
```

### Get Group Invite Link

```python
# Get the group's invite link
invite_link = await client.get_group_invite_link("1234567890-1234567890@g.us")
print(f"Group invite link: {invite_link}")

# Reset the invite link (generate a new one)
new_invite_link = await client.get_group_invite_link("1234567890-1234567890@g.us", reset=True)
print(f"New group invite link: {new_invite_link}")
```

### Join a Group

```python
# Join a group using an invite code (part after chat.whatsapp.com/)
invite_code = "ABC123xyz"  # From https://chat.whatsapp.com/ABC123xyz
group_info = await client.join_group(invite_code)
print(f"Joined group: {group_info['subject']}")
```

### Leave a Group

```python
# Leave a group
success = await client.leave_group("1234567890-1234567890@g.us")
if success:
    print("Successfully left the group")
else:
    print("Failed to leave the group")
```

### Manage Group Settings

```python
# Only allow admins to send messages
await client.set_group_setting(
    group_jid="1234567890-1234567890@g.us",
    setting="announcement",
    value=True
)

# Allow all participants to edit group info
await client.set_group_setting(
    group_jid="1234567890-1234567890@g.us",
    setting="restrict",
    value=False
)

# Enable disappearing messages
await client.set_group_setting(
    group_jid="1234567890-1234567890@g.us",
    setting="ephemeral",
    value=True
)

# Promote participants to admin
result = await client.set_group_admins(
    group_jid="1234567890-1234567890@g.us",
    participant_jids=["1234567890@s.whatsapp.net"],
    promote=True
)
print(f"Promoted admins: {result['succeeded']}")
if result['failed']:
    print(f"Failed to promote: {result['failed']}")

# Demote participants from admin
result = await client.set_group_admins(
    group_jid="1234567890-1234567890@g.us",
    participant_jids=["1234567890@s.whatsapp.net"],
    promote=False
)
print(f"Demoted admins: {result['succeeded']}")
if result['failed']:
    print(f"Failed to demote: {result['failed']}")

# Get group invite information
invite_code = "ABC123xyz"  # From https://chat.whatsapp.com/ABC123xyz
try:
    invite_info = await client.get_group_invite_info(invite_code)
    print(f"Group: {invite_info['subject']}")
    print(f"Created by: {invite_info['creator']}")
    print(f"Members: {invite_info['participant_count']}")
    if invite_info['description']:
        print(f"Description: {invite_info['description']}")
    print(f"Invite link: https://chat.whatsapp.com/{invite_info['invite_code']}")
except Exception as e:
    print(f"Error getting invite info: {e}")

# Control group membership approval
# Lock the group (requires admin approval to join)
locked = await client.set_group_locked(
    group_jid="1234567890-1234567890@g.us",
    locked=True
)
print(f"Group is now {'locked' if locked else 'unlocked'}")

# Unlock the group (anyone with the link can join)
unlocked = await client.set_group_locked(
    group_jid="1234567890-1234567890@g.us",
    locked=False
)
print(f"Group is now {'locked' if not unlocked else 'unmuted'}")

# Mute group notifications
muted = await client.set_group_mute(
    group_jid="1234567890-1234567890@g.us",
    mute_duration=604800  # 1 week
)
print(f"Group is now {'muted' if muted else 'unmuted'}")

# Unmute the group
unmuted = await client.set_group_mute(
    group_jid="1234567890-1234567890@g.us",
    mute_duration=0  # 0 to unmute
)
print(f"Group is now {'muted' if not unmuted else 'unmuted'}")

# Mute for different durations
await client.set_group_mute(group_jid, 3600)    # 1 hour
await client.set_group_mute(group_jid, 28800)   # 8 hours
await client.set_group_mute(group_jid, 604800)  # 1 week
await client.set_group_mute(group_jid, 2419200) # 4 weeks (1 month)

# Get detailed group information
try:
    group_info = await client.get_group_info("1234567890-1234567890@g.us")
    print(f"Group: {group_info['subject']}")
    print(f"Created by: {group_info['creator']} on {datetime.fromtimestamp(group_info['creation'])}")
    print(f"Participants: {group_info['participant_count']}")
    print(f"Description: {group_info.get('description', 'No description')}")
    print(f"Locked: {group_info['locked']}")
    print(f"Announcement mode: {group_info['announcement']}")
    print(f"Restricted: {group_info['restrict']}")

    # List admins
    admins = [p for p in group_info['participants'] if p['is_admin']]
    print(f"\nAdmins ({len(admins)}):")
    for admin in admins:
        print(f"- {admin['jid']} {'(super admin)' if admin['is_super_admin'] else ''}")

    # List regular participants
    regulars = [p for p in group_info['participants'] if not p['is_admin']]
    if regulars:
        print(f"\nRegular participants ({len(regulars)}):")
        for user in regulars[:5]:  # Show first 5
            print(f"- {user['jid']}")
        if len(regulars) > 5:
            print(f"- ... and {len(regulars) - 5} more")

except Exception as e:
    print(f"Error getting group info: {e}")

# Set group icon
try:
    result = await client.set_group_icon(
        group_jid="1234567890-1234567890@g.us",
        image_path="/path/to/group_icon.jpg"
    )
    print(f"Group icon updated successfully!")
    print(f"Icon URL: {result['url']}")
    print(f"Icon ID: {result['id']}")
    print(f"Icon tag: {result['tag']}")
except FileNotFoundError as e:
    print(f"Error: {e}")
except ValueError as e:
    print(f"Invalid image: {e}")
except PymeowError as e:
    print(f"Failed to update group icon: {e}")

# Remove group icon
try:
    success = await client.remove_group_icon("1234567890-1234567890@g.us")
    if success:
        print("Group icon removed successfully!")
    else:
        print("Failed to remove group icon")
except PymeowError as e:
    print(f"Error removing group icon: {e}")
```

## Supported Image Formats
- JPEG (.jpg, .jpeg)
- PNG (.png)
- WebP (.webp)

## Image Requirements
- Recommended size: 640x640 pixels
- Maximum file size: 5MB
- Square aspect ratio works best

Don't forget to import datetime at the top of your script:
```python
from datetime import datetime
```


### Manage Group Participants

```python
# Add and remove participants
result = await client.update_group_participants(
    group_jid="1234567890-1234567890@g.us",
    add_participants=["1234567890@s.whatsapp.net"],
    remove_participants=["0987654321@s.whatsapp.net"]
)

print(f"Added: {result['added']}")
print(f"Removed: {result['removed']}")
if result['failed']:
    print(f"Failed: {result['failed']}")

# Get group invite QR code
try:
    qr_info = await client.get_group_invite_qr("1234567890-1234567890@g.us")
    print(f"Invite URL: {qr_info['invite_url']}")
    print(f"Expires at: {datetime.fromtimestamp(qr_info['expiration'])}" if qr_info['expiration'] > 0 else "Never expires")
except PymeowError as e:
    print(f"Error getting invite QR: {e}")

# Get group invite info
try:
    invite_info = await client.get_group_invite_info("ABC123")
    print(f"Group: {invite_info['subject']}")
    print(f"Created by: {invite_info['creator']}")
    print(f"Members: {invite_info['participant_count']}")
    if invite_info['description']:
        print(f"Description: {invite_info['description']}")
    print(f"Invite expires: {datetime.fromtimestamp(invite_info['expiration'])}" if invite_info['expiration'] > 0 else "Invite never expires")
except PymeowError as e:
    print(f"Error getting invite info: {e}")

# Set group description
try:
    desc_info = await client.set_group_description(
        group_jid="1234567890-1234567890@g.us",
        description="Welcome to our awesome group!"
    )
    print(f"Description set at {datetime.fromtimestamp(desc_info['time'])}")
except PymeowError as e:
    print(f"Error setting description: {e}")

# Get group settings
try:
    settings = await client.get_group_settings("1234567890-1234567890@g.us")
    print("\nGroup Settings:")
    print(f"- Announcement mode: {'Only admins' if settings['announcement'] else 'Everyone'}")
    print(f"- Edit group info: {'Admins only' if settings['restrict'] else 'All participants'}")
    print(f"- Group join: {'Admin approval required' if settings['locked'] else 'Open'}")
    if settings['ephemeral'] > 0:
        print(f"- Disappearing messages: {settings['ephemeral'] // 86400} days")
    else:
        print("- Disappearing messages: Off")
except PymeowError as e:
    print(f"Error getting group settings: {e}")
```

Make sure to import datetime at the top of your script:
```python
from datetime import datetime
```

### Get Group Info

```python
# Get information about a group
group_info = await client.get_group_info("1234567890-1234567890@g.us")
print(f"Group: {group_info['subject']}")
print(f"Created by: {group_info['creator']}")
print(f"Participants: {len(group_info['participants'])}")
```

## Message Status and Read Receipts

Pymeow provides comprehensive message status tracking and read receipt functionality:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    # Define a message status handler
    async def handle_message_status(status):
        print(f"📊 Message status update: {status}")

        if status['status'] == 'delivered':
            print(f"📨 Message delivered to {len(status.get('recipients', []))} recipients")
        elif status['status'] == 'read':
            print(f"👀 Message read by: {', '.join(status.get('read_by', []))}")

    try:
        # Connect and authenticate...
        await client.connect()

        # Add status handler
        client.add_message_status_handler(handle_message_status)

        # Send a message
        print("📤 Sending message...")
        message = await client.send_message(
            to_jid="1234567890@s.whatsapp.net",
            content="Hello, this is a test message!"
        )

        message_id = message['message_id']
        print(f"Message sent with ID: {message_id}")

        # Track message status
        print("\n🔍 Tracking message status...")
        status = await client.track_message_status(message_id)
        print(f"Current status: {status['status']}")

        # In a real app, you would typically check status periodically
        # or wait for status update callbacks

        # Example of marking messages as read (for incoming messages)
        print("\n📝 Marking messages as read...")
        read_status = await client.mark_messages_read(["incoming_msg_id_1", "incoming_msg_id_2"])
        print(f"Marked {len(read_status['message_ids'])} messages as read")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        # Clean up
        client.remove_message_status_handler(handle_message_status)
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Advanced Message Features

Pymeow supports advanced message features like disappearing messages and message pinning:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    try:
        # Connect and authenticate...
        await client.connect()

        chat_jid = "1234567890@s.whatsapp.net"

        # Set disappearing messages (24 hours)
        print("⏳ Setting disappearing messages...")
        await client.set_disappearing_messages(
            chat_jid=chat_jid,
            duration_seconds=86400  # 24 hours
        )

        # Get current disappearing messages settings
        print("\n🔍 Getting disappearing messages settings...")
        settings = await client.get_disappearing_messages(chat_jid)
        print(f"Current settings: {settings}")

        # Pin a message
        print("\n📌 Pinning a message...")
        message_id = "3EB0ABCD1234"
        await client.pin_message(
            chat_jid=chat_jid,
            message_id=message_id,
            unpin_others=True  # Unpin other messages in the chat
        )

        # Get all pinned messages
        print("\n📋 Getting pinned messages...")
        pinned = await client.get_pinned_messages(chat_jid)
        print(f"Pinned messages: {pinned}")

        # Unpin all messages
        print("\n🗑️  Unpinning all messages...")
        await client.unpin_message(chat_jid)

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Message Management

Pymeow provides comprehensive message management features including editing, forwarding, and more:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    try:
        # Connect and authenticate...
        await client.connect()

        # Example chat and message IDs
        chat_jid = "1234567890@s.whatsapp.net"
        target_chat_jid = "9876543210@s.whatsapp.net"
        message_id = "3EB0ABCD1234"

        # Edit a message
        print("✏️  Editing message...")
        edit_result = await client.edit_message(
            message_id=message_id,
            chat_jid=chat_jid,
            new_content="This is the edited message!"
        )
        print(f"Message edited: {edit_result}")

        # Forward a message to another chat
        print("\n↪️  Forwarding message...")
        forward_result = await client.forward_messages(
            message_ids=message_id,
            from_chat_jid=chat_jid,
            to_chat_jid=target_chat_jid
        )
        print(f"Message forwarded: {forward_result}")

        # Forward multiple messages
        print("\n🔄 Forwarding multiple messages...")
        multi_forward_result = await client.forward_messages(
            message_ids=["MSG1", "MSG2", "MSG3"],
            from_chat_jid=chat_jid,
            to_chat_jid=target_chat_jid
        )
        print(f"Messages forwarded: {multi_forward_result}")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Message Interactions

Pymeow supports rich message interactions including reactions and replies:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    try:
        # Connect and authenticate...
        await client.connect()

        # Example chat and message ID (in a real app, you'd get these from user interaction)
        chat_jid = "1234567890@s.whatsapp.net"
        message_id = "3EB0ABCD1234"

        # Send a reaction (emoji) to a message
        print("🎭 Sending reaction...")
        reaction = await client.send_reaction(
            message_id=message_id,
            chat_jid=chat_jid,
            emoji="👍"  # Use empty string to remove reaction
        )
        print(f"Reaction sent: {reaction}")

        # Get reactions for a message
        print("\n🔄 Getting message reactions...")
        reactions = await client.get_message_reactions(message_id, chat_jid)
        print(f"Reactions: {reactions}")

        # Reply to a message
        print("\n↩️  Sending reply...")
        reply = await client.send_reply(
            to_message_id=message_id,
            chat_jid=chat_jid,
            content="This is a reply to your message!"
        )
        print(f"Reply sent: {reply}")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Message History and Search

Pymeow provides powerful message history and search capabilities:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    try:
        # Connect and authenticate...
        await client.connect()

        # Get message history for a chat
        chat_jid = "1234567890@s.whatsapp.net"
        messages = await client.get_message_history(
            chat_jid=chat_jid,
            count=50
        )

        print(f"📜 Last {len(messages)} messages:")
        for msg in messages:
            print(f"{msg.get('from', 'You')}: {msg.get('content', '[Media]')}")

        # Search for messages
        print("\n🔍 Searching for 'hello'...")
        results = await client.search_messages(
            query="hello",
            in_chat=chat_jid,
            max_results=10
        )

        print("\n🔍 Search results:")
        for result in results:
            if result['type'] == 'message':
                print(f"💬 {result['data'].get('from')}: {result['data'].get('content')}")

        # Get a specific message by ID
        if messages:
            print("\n📩 Getting specific message:")
            message = await client.get_message_by_id(messages[0]['id'])
            if message:
                print(f"Message content: {message.get('content')}")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Media Handling

Pymeow supports sending various types of media including images, videos, and documents:

```python
import asyncio
from pymeow import Client

async def main():
    client = Client()

    try:
        # Connect and authenticate...
        await client.connect()

        # Send an image with caption and view-once
        print("📸 Sending image...")
        await client.send_image(
            to="1234567890@s.whatsapp.net",
            image_path="photo.jpg",
            caption="Check this out!",
            view_once=True  # Makes the image disappear after viewing
        )

        # Send a video as a GIF (looping video)
        print("\n🎬 Sending video as GIF...")
        await client.send_video(
            to="1234567890@s.whatsapp.net",
            video_path="animation.mp4",
            gif=True,
            caption="Look at this cool animation!"
        )

        # Send a document with a custom filename
        print("\n📄 Sending document...")
        await client.send_document(
            to="1234567890@s.whatsapp.net",
            file_path="/path/to/document.pdf",
            caption="Here's the file you requested",
            file_name="important_document.pdf"
        )

        # Track upload progress
        print("\n📤 Uploading with progress tracking...")
        def progress_callback(uploaded: int, total: int):
            percent = (uploaded / total) * 100
            print(f"Upload progress: {percent:.1f}%")

        await client.send_document(
            to="1234567890@s.whatsapp.net",
            file_path="/path/to/large_file.zip",
            progress_callback=progress_callback
        )

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### QR Code Authentication

To handle QR code authentication, you'll need to generate a QR code from the `qr` event data:

```python
import qrcode
from io import StringIO

# Inside your QR event handler:
@client.on('qr')
async def on_qr(qr_data):
    print("Scan the QR code to log in:")
    qr = qrcode.QRCode()
    qr.add_data(qr_data)
    qr.print_ascii()

    # Or save to a file
    img = qrcode.make(qr_data)
    img.save("whatsapp_qr.png")
    print("QR code saved as whatsapp_qr.png")
```

### Persistent Authentication

To persist the authentication state between restarts, you can save and load the auth state:

```python
import json

# Save auth state
def save_auth(auth_state, filename="auth.json"):
    with open(filename, "w") as f:
        json.dump(auth_state.to_dict(), f)

# Load auth state
def load_auth(filename="auth.json"):
    try:
        with open(filename, "r") as f:
            return AuthState.from_dict(json.load(f))
    except FileNotFoundError:
        return None

# Usage
auth = load_auth() or AuthState()
client = Client(auth_state=auth)

# After successful authentication
save_auth(auth)
```

## Documentation

### Client Class

The `Client` class is the main entry point for interacting with the Web API.

#### Initialization

```python
from pymeow import Client, AuthState

# Basic initialization
client = Client()

# With authentication state and custom settings
import aiohttp
import logging

auth = AuthState()  # Persistent authentication state
client = Client(
    auth_state=auth,  # Optional: for persistent sessions
    session=None,     # Optional: custom aiohttp.ClientSession
    log_level=logging.INFO  # Logging level
)
```

#### Core Methods

- `connect()`: Connect to Web and start the WebSocket connection
  - Returns: `None`
  - Raises: `ConnectionError` if connection fails
  - Raises: `AuthenticationError` if authentication fails

- `disconnect()`: Disconnect from Web and clean up resources
  - Returns: `None`

- `on(event, handler)`: Decorator to register event handlers
  - `event`: Event name (e.g., 'message', 'connected')
  - `handler`: Async function to handle the event

### Authentication

The client handles authentication automatically using the Noise Protocol. You can manage the authentication state using the `AuthState` class:

```python
from pymeow import AuthState

# Create a new auth state
auth = AuthState()

# Save/load state (for persistence)
state_dict = auth.to_dict()
new_auth = AuthState.from_dict(state_dict)
```

### Events

Available events:

- `connected`: Fired when the WebSocket connection is established
- `authenticated`: Fired after successful authentication
- `disconnected`: Fired when the connection is closed
- `qr`: Fired when a QR code is required for authentication
- `message`: Fired when a new message is received
- `error`: Fired when an error occurs

#### Example: Sending a Message

```python
async def send_test_message():
    client = Client()
    try:
        await client.connect()
        await client.send_message(
            to="1234567890@s.whatsapp.net",
            content="Hello from pymeow!"
        )
    finally:
        await client.disconnect()
```

## Group Management

PyMeow provides comprehensive group management capabilities. For detailed documentation and examples, see the [Group Management Guide](./docs/group_management.md).

### Key Features
- Create and manage groups
- Add/remove participants
- Promote/demote group admins
- Configure group settings (announcements, restrictions, etc.)
- Handle group metadata and invite links

### Quick Example
```python
# Create a new group
group = await client.create_group(
    subject="My Awesome Group",
    participants=["1234567890@s.whatsapp.net"]
)

# Update group settings
await client.set_group_setting(group['id'], "announcement", True)
await client.set_group_setting(group['id'], "ephemeral", 86400)  # 1 day
```

## Advanced Usage

### Customizing the WebSocket Connection

You can customize the WebSocket connection by providing your own WebSocket client implementation:

```python
from pymeow.websocket import WebSocketClient

class CustomWebSocket(WebSocketClient):
    async def connect(self):
        # Custom connection logic
        pass

    async def send(self, data):
        # Custom send logic
        pass

## Contact Management

Pymeow provides comprehensive contact management capabilities. Here's how to work with contacts:

### Get Contact Information

```python
# Get information about a specific contact
contact = await client.get_contact_info("1234567890@s.whatsapp.net")
print(f"Contact name: {contact['name']}")
print(f"Status: {contact['status']}")
print(f"Last seen: {contact['status_timestamp']}")
print(f"Is verified: {contact['is_verified']}")
```

### Get All Contacts

```python
# Get all contacts from your address book
contacts = await client.get_contacts()
for contact in contacts:
    print(f"{contact['name']} ({contact['jid']}): {contact['status']}")
```

### Update Contact Name

```python
# Update a contact's name
success = await client.update_contact_name(
    jid="1234567890@s.whatsapp.net",
    first_name="John",
    full_name="John Doe"
)
if success:
    print("Contact name updated successfully")
```

### Block and Unblock Contacts

```python
# Block a contact
blocked = await client.block_contact("spammer@whatsapp.net")
if blocked:
    print("Contact blocked successfully")

# Unblock a contact
unblocked = await client.unblock_contact("forgiven@whatsapp.net")
if unblocked:
    print("Contact unblocked successfully")
```

### Contact Management in Practice

Here's a complete example that demonstrates contact management:

```python
import asyncio
from pymeow import Client

async def manage_contacts():
    client = Client()

    try:
        # Connect to WhatsApp
        await client.connect()

        # Get all contacts
        print("\n=== My Contacts ===")
        contacts = await client.get_contacts()
        for contact in contacts[:5]:  # Show first 5 contacts
            print(f"- {contact.get('name', 'No name')}: {contact.get('status', 'No status')}")

        # Get info for a specific contact
        print("\n=== Contact Info ===")
        contact = await client.get_contact_info("1234567890@s.whatsapp.net")
        if contact:
            print(f"Name: {contact.get('name', 'N/A')}")
            print(f"Status: {contact.get('status', 'No status')}")
            print(f"Last seen: {contact.get('status_timestamp', 0)}")

        # Update a contact's name
        print("\n=== Updating Contact ===")
        updated = await client.update_contact_name(
            jid="1234567890@s.whatsapp.net",
            first_name="John",
            full_name="John Doe"
        )
        if updated:
            print("Contact name updated successfully")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.disconnect()

# Run the example
if __name__ == "__main__":
    asyncio.run(manage_contacts())
```

### Privacy Settings

Pymeow allows you to manage your privacy settings programmatically. Here's how to use the privacy features:

```python
import asyncio
from pymeow import Client, PrivacySetting

async def manage_privacy():
    client = Client()

    try:
        # Connect to WhatsApp
        await client.connect()

        # Get all privacy settings
        print("\n=== Current Privacy Settings ===")
        settings = await client.get_privacy_settings()
        for setting, value in settings.items():
            print(f"- {setting}: {value}")

        # Update last seen privacy
        print("\n🔒 Updating last seen privacy...")
        await client.set_last_seen_privacy(PrivacySetting.CONTACTS)

        # Update profile photo privacy
        print("\n📸 Updating profile photo privacy...")
        await client.set_profile_photo_privacy(PrivacySetting.CONTACTS)

        # Update status privacy
        print("\n🔄 Updating status privacy...")
        await client.set_status_privacy(PrivacySetting.CONTACTS)

        # Update groups privacy (who can add you to groups)
        print("\n👥 Updating groups privacy...")
        await client.set_groups_privacy(PrivacySetting.CONTACTS)

        # Verify changes
        print("\n✅ Updated Privacy Settings:")
        updated = await client.get_privacy_settings()
        for setting, value in updated.items():
            print(f"- {setting}: {value}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.disconnect()

# Run the example
if __name__ == "__main__":
    asyncio.run(manage_privacy())
```

### Available Privacy Settings

You can control the following privacy settings:

- **Last Seen**: Who can see your last seen timestamp
- **Profile Photo**: Who can see your profile photo
- **Status**: Who can see your status updates
- **About**: Who can see your about info
- **Groups**: Who can add you to groups
- **Calls**: Who can call you

### Privacy Setting Values

Each setting can be one of:

- `PrivacySetting.ALL`: Everyone can see/call/add you
- `PrivacySetting.CONTACTS`: Only your contacts can see/call/add you
- `PrivacySetting.CONTACT_BLACKLIST`: Everyone except blocked contacts
- `PrivacySetting.MATCH_LAST_SEEN`: Same as your last seen setting
- `PrivacySetting.NONE`: No one can see/call/add you (not available for all settings)

## Contact Information Structure

Contact information is returned as dictionaries with the following structure:

```python
{
    'jid': '1234567890@s.whatsapp.net',  # Contact's JID
    'name': 'John Doe',                   # Full name
    'notify': 'John',                     # Notification name
    'short_name': 'John',                 # Short name
    'is_contact': True,                   # Whether the contact is in your address book
    'is_verified': False,                 # Whether the contact is verified
    'push_name': 'John',                  # Push notification name
    'status': 'Available',                # Status message
    'status_timestamp': 1620000000        # Timestamp of last status update
}
```
    async def receive(self):
        # Custom receive logic
        pass

# Use custom WebSocket client
client = Client(websocket_factory=CustomWebSocket)
```

### Error Handling

Handle different types of errors:

```python
try:
    await client.connect()
except ConnectionError as e:
    print(f"Connection failed: {e}")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
```

## Development

### Running Tests

```bash
set PYTHONIOENCODING=utf-8
set LANG=en_US.UTF-8
uv sync
pytest tests/
```

### Building the Package

```bash
python -m build
```

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [whatsmeow](https://github.com/tulir/whatsmeow) - The Go implementation this project is based on
