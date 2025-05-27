"""
Group icon management functionality.
"""
import os
import imghdr
import tempfile
from typing import Dict, Any
from .exceptions import PymeowError

class GroupIconManager:
    """Helper class for managing group icons."""

    def __init__(self, client):
        """Initialize with a client instance."""
        self.client = client

    async def set_group_icon(self, group_jid: str, image_path: str) -> Dict[str, Any]:
        """
        Set or update the group's profile picture.

        Args:
            group_jid: The JID of the group
            image_path: Path to the image file to set as group icon

        Returns:
            Dictionary containing the result of the operation with keys:
            - 'url': URL of the uploaded icon
            - 'tag': The tag/hash of the icon
            - 'id': The ID of the icon

        Raises:
            PymeowError: If setting the icon fails
            FileNotFoundError: If the image file doesn't exist
            ValueError: If the file is not a valid image
        """
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")

        # Read and validate the image
        with open(image_path, 'rb') as f:
            image_data = f.read()

        # Validate it's an image by checking magic numbers
        if not imghdr.what(None, h=image_data):
            raise ValueError("File is not a valid image")

        # Save the image to a temporary file for upload
        _, ext = os.path.splitext(image_path)
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as temp_file:
            temp_file.write(image_data)
            temp_file_path = temp_file.name

        try:
            # Upload the image to get a URL
            media_info = await self.client.upload_media(
                file_path=temp_file_path,
                media_type='image'
            )

            # Get the MIME type of the image
            mime_type = f"image/{ext[1:].lower()}"  # Remove the dot from extension
            if mime_type == 'image/jpg':
                mime_type = 'image/jpeg'  # Standardize jpg to jpeg

            # Generate a unique ID for the icon
            icon_id = self.client._generate_message_id()

            # Create the picture node
            picture_node = self.client.ProtocolNode(
                tag='picture',
                attrs={
                    'id': icon_id,
                    'type': 'image',
                    'url': media_info['url'],
                    'media_key': media_info.get('direct_path', '').split('/')[-1] if media_info.get('direct_path') else '',
                    'mimetype': mime_type
                }
            )

            # Create the IQ node
            iq_id = self.client._generate_message_id()
            iq_node = self.client.ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:profile:picture'
                },
                content=[picture_node]
            )

            # Send and wait for response
            response = await self.client._send_iq_and_wait(iq_node, iq_id)

            # Check if the icon was set successfully
            if response.attrs.get('type') != 'result':
                raise PymeowError("Failed to set group icon")

            return {
                'url': media_info['url'],
                'tag': media_info.get('direct_path', '')[:32],  # First 32 chars as tag
                'id': icon_id
            }

        except Exception as e:
            self.client.logger.error(f"Error setting group icon: {e}", exc_info=True)
            if not isinstance(e, (PymeowError, FileNotFoundError, ValueError)):
                raise PymeowError(f"Failed to set group icon: {e}") from e
            raise

        finally:
            # Clean up the temporary file
            try:
                os.unlink(temp_file_path)
            except (OSError, UnboundLocalError):
                pass
