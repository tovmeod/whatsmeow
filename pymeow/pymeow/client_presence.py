from typing import Optional

from .types.presence import Presence, ChatPresence, ChatPresenceMedia, PresenceEvent, ChatPresenceEvent
from .exceptions import PymeowError


class ClientPresenceMixin:
    """Mixin class that adds presence-related functionality to the client."""

    async def send_presence(self, state: Presence) -> None:
        """Update the user's presence status on WhatsApp.

        You should call this at least once after connecting so that the server has your pushname.
        Otherwise, other users will see "-" as the name.

        Args:
            state: The new presence state (available/unavailable)

        Raises:
            PymeowError: If no pushname is set or if there's an error sending the presence
        """
        if not self.push_name:
            raise PymeowError("No pushname set. Set a pushname before sending presence.")

        # Update active receipts based on presence
        self._send_active_receipts = (state == Presence.AVAILABLE)

        # Build and send presence node
        node = {
            "tag": "presence",
            "attrs": {
                "name": self.push_name,
                "type": state.value,
            },
        }
        await self.send_node(node)

    async def subscribe_presence(self, jid: str) -> None:
        """Ask the WhatsApp servers to send presence updates for a specific user.

        After subscribing to a user, you'll receive presence updates for them in the event handlers.

        Note: You should be online (send_presence(Presence.AVAILABLE)) to receive presence updates.

        Args:
            jid: The JID of the user to subscribe to

        Raises:
            PyMeowError: If there's an error subscribing to the presence
        """
        # TODO: Implement privacy token handling similar to whatsmeow
        node = {
            "tag": "presence",
            "attrs": {
                "type": "subscribe",
                "to": jid,
            },
        }
        await self.send_node(node)

    async def send_chat_presence(
        self,
        jid: str,
        state: ChatPresence,
        media: ChatPresenceMedia = ChatPresenceMedia.TEXT,
    ) -> None:
        """Update the user's typing/recording status in a chat.

        Args:
            jid: The JID of the chat
            state: The new chat presence state (composing/paused)
            media: The type of media being composed (default: text)

        Raises:
            PyMeowError: If not logged in or if there's an error sending the chat presence
        """
        if not self.phone_number:
            raise PymeowError("Not logged in")

        content = [{"tag": state.value}]

        # Add media attribute if composing and media is specified
        if state == ChatPresence.COMPOSING and media != ChatPresenceMedia.TEXT:
            content[0]["attrs"] = {"media": media.value}

        node = {
            "tag": "chatstate",
            "attrs": {
                "from": self.phone_number,
                "to": jid,
            },
            "content": content,
        }
        await self.send_node(node)

    async def _handle_presence(self, node: dict) -> None:
        """Handle an incoming presence update.

        Internal method called when a presence node is received.

        Args:
            node: The presence node
        """
        attrs = node.get("attrs", {})
        from_jid = attrs.get("from")
        presence_type = attrs.get("type")

        if not from_jid:
            self.logger.warning("Received presence update without from JID: %s", node)
            return

        event = PresenceEvent(
            from_jid=from_jid,
            unavailable=(presence_type == "unavailable"),
        )

        # Handle last seen timestamp if available
        last_seen = attrs.get("last")
        if last_seen and last_seen != "deny":
            try:
                event.last_seen = int(last_seen)
            except (TypeError, ValueError):
                self.logger.warning("Invalid last seen timestamp: %s", last_seen)

        await self.dispatch_event("presence", event)

    async def _handle_chat_state(self, node: dict) -> None:
        """Handle an incoming chat state update (typing/recording indicator).

        Internal method called when a chatstate node is received.

        Args:
            node: The chatstate node
        """
        attrs = node.get("attrs", {})
        from_jid = attrs.get("from")
        to_jid = attrs.get("to")

        if not from_jid or not to_jid:
            self.logger.warning("Received chat state without from/to JIDs: %s", node)
            return

        # Find the presence state in the content
        content = node.get("content", [])
        if not content or not isinstance(content, list) or "tag" not in content[0]:
            self.logger.warning("Invalid chat state content: %s", content)
            return

        state_tag = content[0]["tag"]
        try:
            state = ChatPresence(state_tag)
        except ValueError:
            self.logger.warning("Unknown chat presence state: %s", state_tag)
            return

        # Get media type if present
        media = ChatPresenceMedia.TEXT
        if state == ChatPresence.COMPOSING and "attrs" in content[0]:
            media_attr = content[0]["attrs"].get("media")
            if media_attr:
                try:
                    media = ChatPresenceMedia(media_attr)
                except ValueError:
                    self.logger.warning("Unknown chat presence media: %s", media_attr)

        event = ChatPresenceEvent(
            from_jid=from_jid,
            to_jid=to_jid,
            state=state,
            media=media,
        )

        await self.dispatch_event("chat_presence", event)
