# Group Management

PyMeow provides comprehensive group management capabilities. This document covers all available group-related methods and their usage.

## Table of Contents
- [Creating Groups](#creating-groups)
- [Getting Group Information](#getting-group-information)
- [Managing Group Settings](#managing-group-settings)
- [Managing Participants](#managing-participants)
- [Group Metadata](#group-metadata)
- [Leaving Groups](#leaving-groups)

## Creating Groups

### `create_group(subject: str, participants: List[str]) -> Dict[str, Any]`

Create a new group with the specified subject and participants.

**Parameters:**
- `subject` (str): The group subject/name
- `participants` (List[str]): List of JIDs to add to the group

**Returns:**
- `Dict[str, Any]`: Group creation details including group ID and creation timestamp

**Example:**
```python
# Create a new group
result = await client.create_group(
    subject="My New Group",
    participants=["1234567890@s.whatsapp.net", "0987654321@s.whatsapp.net"]
)
print(f"Created group with ID: {result['id']}")
```

## Getting Group Information

### `get_group_info(group_jid: str) -> Dict[str, Any]`

Get detailed information about a group.

**Parameters:**
- `group_jid` (str): The JID of the group

**Returns:**
- `Dict[str, Any]`: Group information including participants, settings, and metadata

**Example:**
```python
# Get group info
group_info = await client.get_group_info("1234567890-12345678@g.us")
print(f"Group name: {group_info['subject']}")
print(f"Created by: {group_info['creator']}")
print(f"Participants: {len(group_info['participants'])}")
```

### `get_joined_groups() -> List[Dict[str, Any]]`

Get a list of all groups the user is participating in.

**Returns:**
- `List[Dict[str, Any]]`: List of groups with basic information

**Example:**
```python
# Get list of joined groups
groups = await client.get_joined_groups()
for group in groups:
    print(f"- {group['subject']} ({group['id']})")
```

### `get_group_settings(group_jid: str) -> Dict[str, Any]`

Get the current settings for a group.

**Parameters:**
- `group_jid` (str): The JID of the group

**Returns:**
- `Dict[str, Any]`: Current group settings

**Example:**
```python
# Get group settings
settings = await client.get_group_settings("1234567890-12345678@g.us")
print(f"Announcement mode: {settings['announcement']}")
print(f"Restricted mode: {settings['restrict']}")
print(f"Ephemeral messages: {settings['ephemeral']} seconds")
```

## Managing Group Settings

### `set_group_setting(group_jid: str, setting: str, value: Any) -> bool`

Update a group setting.

**Parameters:**
- `group_jid` (str): The JID of the group
- `setting` (str): The setting to update (see below for available settings)
- `value` (Any): The new value for the setting

**Available Settings:**
- `announcement` (bool): If True, only admins can send messages
- `restrict` (bool): If True, only admins can edit group info
- `ephemeral` (int): Duration for disappearing messages in seconds (0=off, 86400=24h, 604800=7d)
- `locked` (bool): If True, group is locked (requires admin approval to join)
- `incognito` (bool): If True, group is incognito
- `no_frequently_forwarded` (bool): If True, disables frequently forwarded messages
- `membership_approval_mode` (bool): If True, requires admin approval to join

**Returns:**
- `bool`: True if the setting was updated successfully

**Example:**
```python
# Enable admin-only messages
await client.set_group_setting("1234567890-12345678@g.us", "announcement", True)

# Set disappearing messages to 1 day
await client.set_group_setting("1234567890-12345678@g.us", "ephemeral", 86400)
```

### `set_group_subject(group_jid: str, subject: str) -> bool`

Update the group subject/name.

**Parameters:**
- `group_jid` (str): The JID of the group
- `subject` (str): New group subject

**Returns:**
- `bool`: True if the subject was updated successfully

**Example:**
```python
# Change group name
await client.set_group_subject("1234567890-12345678@g.us", "New Group Name")
```

## Managing Participants

### `update_group_participants(group_jid: str, add_participants: List[str] = None, remove_participants: List[str] = None) -> Dict[str, List[str]]`

Add or remove participants from a group.

**Parameters:**
- `group_jid` (str): The JID of the group
- `add_participants` (List[str], optional): List of JIDs to add
- `remove_participants` (List[str], optional): List of JIDs to remove

**Returns:**
- `Dict[str, List[str]]`: Dictionary with 'added' and 'removed' lists

**Example:**
```python
# Add and remove participants
result = await client.update_group_participants(
    group_jid="1234567890-12345678@g.us",
    add_participants=["1234567890@s.whatsapp.net"],
    remove_participants=["0987654321@s.whatsapp.net"]
)
print(f"Added: {result['added']}")
print(f"Removed: {result['removed']}")
```

### `set_group_admins(group_jid: str, participant_jids: List[str], promote: bool = True) -> Dict[str, List[str]]`

Promote or demote group participants to/from admin.

**Parameters:**
- `group_jid` (str): The JID of the group
- `participant_jids` (List[str]): List of participant JIDs to modify
- `promote` (bool): If True, promote to admin; if False, demote

**Returns:**
- `Dict[str, List[str]]`: Dictionary with 'succeeded' and 'failed' lists

**Example:**
```python
# Promote participants to admin
result = await client.set_group_admins(
    group_jid="1234567890-12345678@g.us",
    participant_jids=["1234567890@s.whatsapp.net"],
    promote=True
)
print(f"Promoted: {result['succeeded']}")
```

## Group Metadata

### `get_group_invite_link(group_jid: str, reset: bool = False) -> str`

Get or reset the group's invite link.

**Parameters:**
- `group_jid` (str): The JID of the group
- `reset` (bool): If True, generates a new invite link

**Returns:**
- `str`: The group invite link

**Example:**
```python
# Get group invite link
link = await client.get_group_invite_link("1234567890-12345678@g.us")
print(f"Group invite link: {link}")
```

## Leaving Groups

### `leave_group(group_jid: str) -> bool`

Leave a group.

**Parameters:**
- `group_jid` (str): The JID of the group to leave

**Returns:**
- `bool`: True if left the group successfully

**Example:**
```python
# Leave a group
await client.leave_group("1234567890-12345678@g.us")
```

## Error Handling

All group management methods may raise a `PymeowError` if the operation fails. Always use try/except blocks to handle potential errors:

```python
try:
    await client.create_group("My Group", ["1234567890@s.whatsapp.net"])
except PymeowError as e:
    print(f"Error creating group: {e}")
```
