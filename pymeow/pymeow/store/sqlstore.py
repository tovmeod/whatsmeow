"""
SQL-based store implementation for WhatsApp data.

Port of whatsmeow/store/sqlstore/
"""
from typing import Optional, List, Dict, Any
import sqlite3
import json
from datetime import datetime
import asyncio
from pathlib import Path

from ..store import Store
from ..generated import WAMsgTransport_pb2
from ..generated.waE2E import WAWebProtobufsE2E_pb2
from ..types.message import MessageSource

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    chat_jid TEXT NOT NULL,
    sender_jid TEXT NOT NULL,
    message_data BLOB NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    jid TEXT PRIMARY KEY,
    name TEXT,
    push_name TEXT
);

CREATE TABLE IF NOT EXISTS groups (
    jid TEXT PRIMARY KEY,
    name TEXT,
    topic TEXT,
    created_timestamp INTEGER
);

CREATE TABLE IF NOT EXISTS group_participants (
    group_jid TEXT NOT NULL,
    participant_jid TEXT NOT NULL,
    admin BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (group_jid, participant_jid)
);

CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_jid);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
"""

class SQLStore(Store):
    """SQL-based implementation of the WhatsApp store."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None

    async def connect(self) -> None:
        """Connect to the database and ensure schema."""
        def _connect():
            self._connection = sqlite3.connect(self.db_path)
            cursor = self._connection.cursor()
            cursor.executescript(SCHEMA)
            self._connection.commit()

        await asyncio.get_event_loop().run_in_executor(None, _connect)

    async def save_message(self, msg: WAMsgTransport_pb2.MessageTransport) -> None:
        """Save a message to the store."""
        if not self._connection:
            raise RuntimeError("Store not connected")

        def _save():
            cursor = self._connection.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO messages (message_id, chat_jid, sender_jid, message_data, timestamp) VALUES (?, ?, ?, ?, ?)",
                (
                    msg.key.id,
                    msg.key.remoteJid,
                    msg.key.participant or msg.key.remoteJid,
                    msg.SerializeToString(),
                    int(datetime.now().timestamp())
                )
            )
            self._connection.commit()

        await asyncio.get_event_loop().run_in_executor(None, _save)

    async def get_message(self, message_id: str) -> Optional[WAMsgTransport_pb2.MessageTransport]:
        """Retrieve a message from the store."""
        if not self._connection:
            raise RuntimeError("Store not connected")

        def _get():
            cursor = self._connection.cursor()
            cursor.execute("SELECT message_data FROM messages WHERE message_id = ?", (message_id,))
            row = cursor.fetchone()
            if row:
                msg = WAMsgTransport_pb2.Message()
                msg.ParseFromString(row[0])
                return msg
            return None

        return await asyncio.get_event_loop().run_in_executor(None, _get)

    async def get_contact_name(self, jid: str) -> Optional[str]:
        """Get the name of a contact."""
        if not self._connection:
            raise RuntimeError("Store not connected")

        def _get():
            cursor = self._connection.cursor()
            cursor.execute("SELECT name FROM contacts WHERE jid = ?", (jid,))
            row = cursor.fetchone()
            return row[0] if row else None

        return await asyncio.get_event_loop().run_in_executor(None, _get)

    async def save_contact_name(self, jid: str, name: str) -> None:
        """Save a contact's name."""
        if not self._connection:
            raise RuntimeError("Store not connected")

        def _save():
            cursor = self._connection.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO contacts (jid, name) VALUES (?, ?)",
                (jid, name)
            )
            self._connection.commit()

        await asyncio.get_event_loop().run_in_executor(None, _save)

    async def save_group_participant(self, group_id: str, participant_jid: str) -> None:
        """Save a group participant."""
        if not self._connection:
            raise RuntimeError("Store not connected")

        def _save():
            cursor = self._connection.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO group_participants (group_jid, participant_jid) VALUES (?, ?)",
                (group_id, participant_jid)
            )
            self._connection.commit()

        await asyncio.get_event_loop().run_in_executor(None, _save)

    async def get_group_participants(self, group_id: str) -> List[str]:
        """Get all participants in a group."""
        if not self._connection:
            raise RuntimeError("Store not connected")

        def _get():
            cursor = self._connection.cursor()
            cursor.execute(
                "SELECT participant_jid FROM group_participants WHERE group_jid = ?",
                (group_id,)
            )
            return [row[0] for row in cursor.fetchall()]

        return await asyncio.get_event_loop().run_in_executor(None, _get)
