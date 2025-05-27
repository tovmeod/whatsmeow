"""
PyMeow Message Store - WhatsApp Message Persistence

This module provides persistent storage for WhatsApp messages, contacts, and conversations,
allowing for reliable message delivery tracking, history synchronization, and state management
across application restarts.

WhatsMeow Equivalents:
- store/sqlstore: Main message store implementation (Partially implemented)
- store/container.go: Message container types (Partially implemented)
- store/msgstore: Message storage (Partially implemented)
- store/msgconv: Message conversion utilities (Partially implemented)
- store/msgstore.go: Core message store interface (Partially implemented)
- store/msgstore_handlers.go: Message store handlers (Basic implementation)
- store/msgstore_history_sync.go: History sync handling (Basic implementation)
- store/msgstore_receipts.go: Receipt handling (Basic implementation)
- store/msgstore_retry.go: Retry logic (Basic implementation)
- store/msgstore_status.go: Status handling (Basic implementation)

Key Components:
- MessageStore: Main class for message persistence (store/sqlstore)
- Message: Message data structure (types/message.go)
- ConversationInfo: Conversation metadata (types/conversation.go)
- HistorySyncType: Types of history sync operations (types/history_sync.go)

Implementation Status:
- Message storage: Basic
- Conversation tracking: Basic
- History sync: Partial
- Message status tracking: Basic
- Receipt handling: Basic
- Retry logic: Basic
- Media storage: Not implemented
- End-to-end encryption: Not implemented

Key Differences from WhatsMeow:
- Uses SQLite instead of a custom database layer
- Simplified data model
- Python's async/await pattern
- Integrated with Python's logging system
- More flexible schema for message metadata
- Less aggressive caching strategy
"""
import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from enum import IntEnum
from typing import Dict, List, Optional, Union, Any, AsyncIterator, TypedDict, Literal

logger = logging.getLogger(__name__)


class HistorySyncType(IntEnum):
    """Types of history sync operations."""
    INITIAL_BOOTSTRAP = 0
    FULL = 1
    RECENT = 2
    PUSH_NAME = 3
    NON_BLOCKING = 4
    ON_DEMAND = 5


class SyncState(TypedDict, total=False):
    """State of a sync operation."""
    sync_type: HistorySyncType
    last_sync_timestamp: float
    sync_cursor: str
    progress: int  # 0-100


class ConversationInfo(TypedDict):
    """Information about a conversation."""
    chat_jid: str
    last_message_id: str
    last_message_timestamp: float
    unread_count: int
    is_archived: bool
    is_muted: bool
    is_marked_unread: bool
    last_message: Optional[Dict[str, Any]]

@dataclass
class Message:
    """Represents a message in the store."""
    message_id: str
    to_jid: str
    from_jid: str
    content: str
    message_type: str = 'text'
    status: str = 'pending'  # pending, sent, delivered, read, failed
    timestamp: float = field(default_factory=time.time)
    retry_count: int = 0
    last_attempt: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for serialization."""
        result = asdict(self)
        # Convert datetime objects to ISO format strings
        for field in ['timestamp', 'last_attempt']:
            if field in result and result[field] is not None:
                if isinstance(result[field], float):
                    result[field] = datetime.fromtimestamp(result[field]).isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create a Message from a dictionary."""
        # Convert string timestamps back to floats
        for field in ['timestamp', 'last_attempt']:
            if field in data and data[field] is not None:
                if isinstance(data[field], str):
                    data[field] = datetime.fromisoformat(data[field]).timestamp()
        return cls(**data)


class MessageStore:
    """Persistent message storage using SQLite."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """
        Initialize the message store.

        Args:
            db_path: Path to the SQLite database file. If None, uses in-memory storage.
        """
        self.db_path = Path(db_path) if db_path else None
        self._db: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the database and create tables if they don't exist."""
        if self._initialized:
            return

        if self.db_path and not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        def _init_db(conn: sqlite3.Connection):
            cursor = conn.cursor()

            # Create messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    to_jid TEXT NOT NULL,
                    from_jid TEXT NOT NULL,
                    content TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_attempt REAL,
                    error TEXT,
                    metadata TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')

            # Create reactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reactions (
                    reaction_id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    sender_jid TEXT NOT NULL,
                    emoji TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    is_removed INTEGER NOT NULL DEFAULT 0,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (message_id) REFERENCES messages(message_id) ON DELETE CASCADE,
                    UNIQUE(message_id, sender_jid)
                )
            ''')

            # Add new columns to messages table if they don't exist
            for column in ['is_deleted', 'is_forwarded', 'is_starred']:
                try:
                    cursor.execute(f'ALTER TABLE messages ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0')
                except sqlite3.OperationalError:
                    # Column already exists
                    pass

            # Create sync state table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sync_state (
                    sync_type TEXT PRIMARY KEY,
                    last_sync_timestamp REAL,
                    sync_cursor TEXT,
                    progress INTEGER DEFAULT 0,
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')

            # Create conversations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS conversations (
                    chat_jid TEXT PRIMARY KEY,
                    last_message_id TEXT,
                    last_message_timestamp REAL,
                    unread_count INTEGER DEFAULT 0,
                    is_archived INTEGER DEFAULT 0,
                    is_muted INTEGER DEFAULT 0,
                    is_marked_unread INTEGER DEFAULT 0,
                    last_message_data TEXT,
                    updated_at REAL DEFAULT (strftime('%s', 'now')),
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (last_message_id) REFERENCES messages(message_id) ON DELETE SET NULL
                )
            ''')

            # Create additional indexes for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_conversations_timestamp ON conversations(last_message_timestamp)')

            # Initialize default sync states if not exists
            for sync_type in HistorySyncType:
                cursor.execute(
                    'INSERT OR IGNORE INTO sync_state (sync_type, progress) VALUES (?, ?)',
                    (sync_type.name, 0)
                )

            conn.commit()

        if self.db_path:
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            _init_db(conn)
            self._db = conn
        else:
            # In-memory database for testing
            conn = sqlite3.connect(':memory:', check_same_thread=False)
            conn.row_factory = sqlite3.Row
            _init_db(conn)
            self._db = conn

        self._initialized = True

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            self._db.close()
            self._db = None
        self._initialized = False

    async def get_sync_state(self, sync_type: HistorySyncType) -> SyncState:
        """
        Get the current sync state for a specific sync type.

        Args:
            sync_type: The type of sync to get state for

        Returns:
            Dictionary containing sync state information
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT * FROM sync_state
            WHERE sync_type = ?
        ''', (sync_type.name,))

        row = cursor.fetchone()
        if not row:
            return {
                'sync_type': sync_type,
                'last_sync_timestamp': 0,
                'sync_cursor': '',
                'progress': 0
            }

        return {
            'sync_type': sync_type,
            'last_sync_timestamp': row['last_sync_timestamp'] or 0,
            'sync_cursor': row['sync_cursor'] or '',
            'progress': row['progress'] or 0
        }

    async def update_sync_state(
        self,
        sync_type: HistorySyncType,
        last_sync_timestamp: Optional[float] = None,
        sync_cursor: Optional[str] = None,
        progress: Optional[int] = None
    ) -> None:
        """
        Update the sync state for a specific sync type.

        Args:
            sync_type: The type of sync to update
            last_sync_timestamp: Timestamp of the last sync
            sync_cursor: Cursor for pagination
            progress: Sync progress (0-100)
        """
        if not self._initialized:
            await self.initialize()

        updates = []
        params = {'sync_type': sync_type.name}

        if last_sync_timestamp is not None:
            updates.append('last_sync_timestamp = :last_sync_timestamp')
            params['last_sync_timestamp'] = last_sync_timestamp

        if sync_cursor is not None:
            updates.append('sync_cursor = :sync_cursor')
            params['sync_cursor'] = sync_cursor

        if progress is not None:
            updates.append('progress = :progress')
            params['progress'] = progress

        if not updates:
            return  # Nothing to update

        query = f'''
            INSERT INTO sync_state (sync_type, {', '.join(updates)})
            VALUES (:sync_type, {', :'.join(updates)})
            ON CONFLICT(sync_type) DO UPDATE SET
                {', '.join(f'{u} = excluded.{u.split()[0]}' for u in updates)},
                updated_at = strftime('%s', 'now')
        '''

        async with self._lock:
            self._db.execute(query, params)
            self._db.commit()

    async def handle_history_sync(self, sync_data: Dict[str, Any]) -> None:
        """
        Process a history sync chunk from the server.

        Args:
            sync_data: Dictionary containing sync data from the server
        """
        if not self._initialized:
            await self.initialize()

        sync_type = HistorySyncType(sync_data.get('sync_type', 0))
        conversations = sync_data.get('conversations', [])
        status_v3_messages = sync_data.get('statusV3Messages', [])

        # Update conversations and messages
        for conv in conversations:
            await self._update_conversation(conv)

        # Process status messages
        for msg in status_v3_messages:
            await self._process_status_message(msg)

        # Update sync state
        await self.update_sync_state(
            sync_type=sync_type,
            last_sync_timestamp=time.time(),
            progress=100 if sync_type != HistorySyncType.INITIAL_BOOTSTRAP else None
        )

    async def _update_conversation(self, conv_data: Dict[str, Any]) -> None:
        """Update conversation information from sync data."""
        chat_jid = conv_data.get('id')
        if not chat_jid:
            return

        last_message = conv_data.get('messages', [{}])[-1] if conv_data.get('messages') else {}

        async with self._lock:
            cursor = self._db.cursor()
            cursor.execute('''
                INSERT INTO conversations (
                    chat_jid,
                    last_message_id,
                    last_message_timestamp,
                    unread_count,
                    is_archived,
                    is_muted,
                    is_marked_unread,
                    last_message_data,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_jid) DO UPDATE SET
                    last_message_id = excluded.last_message_id,
                    last_message_timestamp = excluded.last_message_timestamp,
                    unread_count = excluded.unread_count,
                    is_archived = excluded.is_archived,
                    is_muted = excluded.is_muted,
                    is_marked_unread = excluded.is_marked_unread,
                    last_message_data = excluded.last_message_data,
                    updated_at = excluded.updated_at
            ''', (
                chat_jid,
                last_message.get('key', {}).get('id'),
                last_message.get('messageTimestamp'),
                conv_data.get('unreadCount', 0),
                1 if conv_data.get('archived') else 0,
                1 if conv_data.get('muteExpiration', 0) > 0 else 0,
                1 if conv_data.get('markedAsUnread') else 0,
                json.dumps(last_message) if last_message else None,
                time.time()
            ))
            self._db.commit()

    async def _process_status_message(self, msg_data: Dict[str, Any]) -> None:
        """Process a status update message from sync data."""
        # Implement status message processing logic here
        # This is a placeholder for actual implementation
        pass

    async def get_conversations(
        self,
        limit: int = 100,
        before: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Get list of conversations with their latest messages.

        Args:
            limit: Maximum number of conversations to return
            before: Only return conversations before this timestamp

        Returns:
            List of conversation dictionaries
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()

        query = '''
            SELECT * FROM conversations
            WHERE 1=1
        '''
        params = []

        if before is not None:
            query += ' AND last_message_timestamp < ?'
            params.append(before)

        query += ' ORDER BY last_message_timestamp DESC LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)

        conversations = []
        for row in cursor.fetchall():
            conv = dict(row)
            if conv['last_message_data']:
                try:
                    conv['last_message'] = json.loads(conv['last_message_data'])
                except (json.JSONDecodeError, TypeError):
                    conv['last_message'] = None
            conversations.append(conv)

        return conversations

    async def add_message(self, message: Message) -> None:
        """Add a new message to the store."""
        if not self._initialized:
            await self.initialize()

        async with self._lock:
            cursor = self._db.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO messages
                (message_id, to_jid, from_jid, content, message_type, status,
                 timestamp, retry_count, last_attempt, error, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                message.message_id,
                message.to_jid,
                message.from_jid,
                message.content,
                message.message_type,
                message.status,
                message.timestamp,
                message.retry_count,
                message.last_attempt,
                message.error,
                json.dumps(message.metadata) if message.metadata else None
            ))
            self._db.commit()

    async def get_message(self, message_id: str) -> Optional[Message]:
        """Retrieve a message by its ID."""
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('SELECT * FROM messages WHERE message_id = ?', (message_id,))
        row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_message(row)

    async def update_message_status(
        self,
        message_id: str,
        status: str,
        error: Optional[str] = None,
        increment_retry: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update a message's status.

        Args:
            message_id: The ID of the message to update
            status: New status value
            error: Optional error message
            increment_retry: Whether to increment the retry count
            metadata: Optional metadata to merge with existing metadata

        Returns:
            True if the message was updated, False if not found
        """
        if not self._initialized:
            await self.initialize()

        async with self._lock:
            cursor = self._db.cursor()

            # Get current metadata if we need to merge
            current_metadata = {}
            if metadata is not None:
                cursor.execute('SELECT metadata FROM messages WHERE message_id = ?', (message_id,))
                row = cursor.fetchone()
                if row and row['metadata']:
                    try:
                        current_metadata = json.loads(row['metadata'])
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Merge with new metadata
                current_metadata.update(metadata or {})

            query = '''
                UPDATE messages
                SET status = ?,
                    error = ?,
                    retry_count = retry_count + ?,
                    last_attempt = ?,
                    metadata = ?,
                    updated_at = strftime('%s', 'now')
                WHERE message_id = ?
            '''

            cursor.execute(
                query,
                (
                    status,
                    error,
                    1 if increment_retry else 0,
                    time.time() if increment_retry else None,
                    json.dumps(current_metadata) if current_metadata else None,
                    message_id
                )
            )

            self._db.commit()
            return cursor.rowcount > 0

    async def get_pending_messages(
        self,
        limit: int = 100,
        max_retries: int = 3,
        min_retry_delay: int = 60
    ) -> List[Message]:
        """
        Retrieve messages that are pending delivery or need to be retried.

        Args:
            limit: Maximum number of messages to return
            max_retries: Maximum number of retry attempts
            min_retry_delay: Minimum delay between retries in seconds

        Returns:
            List of pending messages
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT * FROM messages
            WHERE status IN ('pending', 'retrying')
            AND (retry_count < ? OR status = 'pending')
            AND (last_attempt IS NULL OR last_attempt < ?)
            ORDER BY created_at ASC
            LIMIT ?
        ''', (
            max_retries,
            time.time() - min_retry_delay,
            limit
        ))

        return [self._row_to_message(row) for row in cursor.fetchall()]

    async def delete_message(self, message_id: str) -> bool:
        """
        Delete a message from the store.

        Args:
            message_id: The ID of the message to delete

        Returns:
            True if the message was deleted, False if not found
        """
        if not self._initialized:
            await self.initialize()

        async with self._lock:
            cursor = self._db.cursor()
            cursor.execute('DELETE FROM messages WHERE message_id = ?', (message_id,))
            self._db.commit()
            return cursor.rowcount > 0

    async def get_messages_by_status(self, status: str, limit: int = 100) -> List[Message]:
        """
        Retrieve messages with a specific status.

        Args:
            status: Status to filter by
            limit: Maximum number of messages to return

        Returns:
            List of matching messages
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT * FROM messages
            WHERE status = ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (status, limit))

        messages = []
        for row in cursor.fetchall():
            message = self._row_to_message(row)
            # Load reactions for each message
            message.reactions = await self.get_message_reactions(message.message_id)
            messages.append(message)

        return messages

    async def add_reaction(self, message_id: str, sender_jid: str, emoji: str) -> bool:
        """
        Add or update a reaction to a message.

        Args:
            message_id: The ID of the message being reacted to
            sender_jid: The JID of the user who reacted
            emoji: The emoji reaction (empty string to remove)

        Returns:
            bool: True if the reaction was added/updated, False otherwise
        """
        if not self._initialized:
            await self.initialize()

        if not emoji:
            return await self.remove_reaction(message_id, sender_jid)

        reaction_id = f"{message_id}:{sender_jid}"
        timestamp = time.time()

        async with self._lock:
            cursor = self._db.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO reactions
                (reaction_id, message_id, sender_jid, emoji, timestamp, is_removed, updated_at)
                VALUES (?, ?, ?, ?, ?, 0, ?)
            ''', (
                reaction_id,
                message_id,
                sender_jid,
                emoji,
                timestamp,
                timestamp
            ))
            self._db.commit()
            return cursor.rowcount > 0

    async def remove_reaction(self, message_id: str, sender_jid: str) -> bool:
        """
        Remove a reaction from a message.

        Args:
            message_id: The ID of the message
            sender_jid: The JID of the user whose reaction to remove

        Returns:
            bool: True if the reaction was removed, False otherwise
        """
        if not self._initialized:
            await self.initialize()

        reaction_id = f"{message_id}:{sender_jid}"

        async with self._lock:
            cursor = self._db.cursor()
            cursor.execute('''
                UPDATE reactions
                SET is_removed = 1,
                    updated_at = ?
                WHERE reaction_id = ?
            ''', (time.time(), reaction_id))
            self._db.commit()
            return cursor.rowcount > 0

    async def get_message_reactions(self, message_id: str) -> List[Dict[str, Any]]:
        """
        Get all reactions for a message.

        Args:
            message_id: The ID of the message

        Returns:
            List of reaction dictionaries with sender_jid, emoji, and timestamp
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT sender_jid, emoji, timestamp
            FROM reactions
            WHERE message_id = ? AND is_removed = 0
            ORDER BY timestamp ASC
        ''', (message_id,))

        return [
            {
                'sender_jid': row[0],
                'emoji': row[1],
                'timestamp': row[2]
            }
            for row in cursor.fetchall()
        ]

    async def get_reaction_by_sender(self, message_id: str, sender_jid: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific user's reaction to a message.

        Args:
            message_id: The ID of the message
            sender_jid: The JID of the user who reacted

        Returns:
            Dictionary with reaction details or None if no reaction found
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT emoji, timestamp, is_removed
            FROM reactions
            WHERE message_id = ? AND sender_jid = ?
            ORDER BY timestamp DESC
            LIMIT 1
        ''', (message_id, sender_jid))

        row = cursor.fetchone()
        if not row:
            return None

        return {
            'emoji': row[0],
            'timestamp': row[1],
            'is_removed': bool(row[2])
        }

    async def get_reaction_senders(self, message_id: str, emoji: str) -> List[str]:
        """
        Get all users who reacted with a specific emoji to a message.

        Args:
            message_id: The ID of the message
            emoji: The emoji to filter by

        Returns:
            List of JIDs of users who reacted with the emoji
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT sender_jid
            FROM reactions
            WHERE message_id = ? AND emoji = ? AND is_removed = 0
            ORDER BY timestamp ASC
        ''', (message_id, emoji))

        return [row[0] for row in cursor.fetchall()]

    async def get_messages_by_recipient(
        self,
        to_jid: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Message]:
        """
        Retrieve messages sent to a specific JID.

        Args:
            to_jid: Recipient JID
            limit: Maximum number of messages to return
            offset: Number of messages to skip

        Returns:
            List of matching messages
        """
        if not self._initialized:
            await self.initialize()

        cursor = self._db.cursor()
        cursor.execute('''
            SELECT * FROM messages
            WHERE to_jid = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ''', (to_jid, limit, offset))

        return [self._row_to_message(row) for row in cursor.fetchall()]

    @staticmethod
    def _row_to_message(row) -> Message:
        """Convert a database row to a Message object."""
        metadata = {}
        if row['metadata']:
            try:
                metadata = json.loads(row['metadata'])
            except (json.JSONDecodeError, TypeError):
                pass

        return Message(
            message_id=row['message_id'],
            to_jid=row['to_jid'],
            from_jid=row['from_jid'],
            content=row['content'],
            message_type=row['message_type'],
            status=row['status'],
            timestamp=row['timestamp'],
            retry_count=row['retry_count'],
            last_attempt=row['last_attempt'],
            error=row['error'],
            metadata=metadata
        )
