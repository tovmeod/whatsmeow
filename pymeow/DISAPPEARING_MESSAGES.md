# Disappearing Messages in PyMeow

PyMeow now supports disappearing messages feature, allowing you to send messages that automatically disappear after a set period or after being viewed once.

## Table of Contents
- [Sending Disappearing Messages](#sending-disappearing-messages)
- [Setting Disappearing Messages for a Chat](#setting-disappearing-messages-for-a-chat)
- [Getting Current Disappearing Messages Settings](#getting-current-disappearing-messages-settings)
- [Sending View-Once (Ephemeral) Messages](#sending-view-once-ephemeral-messages)
- [Example](#example)

## Sending Disappearing Messages

You can send a disappearing message by specifying the `expiration_seconds` parameter when calling `send_message`:

```python
from py import Client, ExpirationType

# Initialize client...


# Send a message that disappears after 1 hour
await client.send_message(
    to="1234567890@s.whatsapp.net",
    content="This will disappear in 1 hour!",
    expiration_seconds=3600  # 1 hour in seconds
)

# Or use predefined durations
await client.send_message(
    to="1234567890@s.whatsapp.net",
    content="This will disappear in 1 week!",
    expiration_seconds=ExpirationType.ONE_WEEK
)
```

### Available Duration Presets

- `ExpirationType.OFF` (0) - Disable disappearing messages
- `ExpirationType.ONE_DAY` (86400) - 24 hours
- `ExpirationType.ONE_WEEK` (604800) - 7 days
- `ExpirationType.FOUR_WEEKS` (2419200) - 28 days

## Setting Disappearing Messages for a Chat

You can enable or update the disappearing messages setting for an entire chat:

```python
# Set disappearing messages to 1 day for a chat
result = await client.set_disappearing_messages(
    chat_jid="1234567890@s.whatsapp.net",
    duration_seconds=ExpirationType.ONE_DAY
)

# Disable disappearing messages
result = await client.set_disappearing_messages(
    chat_jid="1234567890@s.whatsapp.net",
    duration_seconds=ExpirationType.OFF
)
```

## Getting Current Disappearing Messages Settings

Retrieve the current disappearing messages setting for a chat:

```python
settings = await client.get_disappearing_messages("1234567890@s.whatsapp.net")
print(f"Disappearing messages enabled: {settings['enabled']}")
print(f"Duration: {settings['duration_seconds']} seconds")
```

## Sending View-Once (Ephemeral) Messages

View-once messages disappear after being viewed once by the recipient:

```python
await client.send_message(
    to="1234567890@s.whatsapp.net",
    content="This is a view-once message!",
    is_ephemeral=True
)
```

## Example

See the [disappearing_messages_example.py](examples/disappearing_messages_example.py) file for a complete example of using disappearing messages in PyMeow.

## Notes

- Disappearing messages only work in end-to-end encrypted chats
- The timer starts when the message is delivered, not when it's read
- View-once messages are automatically marked as read when opened
- Some message types (like contacts and locations) can't be set to disappear
- Group admins can enable or disable disappearing messages for the entire group

## Troubleshooting

If disappearing messages aren't working as expected:
1. Make sure both you and the recipient are using the latest version
2. Check that the chat is end-to-end encrypted
3. Verify that disappearing messages are supported for the message type you're trying to send
4. Check the logs for any error messages
