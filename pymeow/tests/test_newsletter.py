"""Test newsletter handling."""
import pytest

from ..pymeow.generated.waMsgTransport import WAMsgTransport_pb2
from ..pymeow.newsletter import NewsletterHandler


@pytest.mark.asyncio
async def test_newsletter_creation():
    """Test creating a newsletter."""
    handler = NewsletterHandler()
    name = "Test Newsletter"
    description = "A test newsletter"
    picture = b"fake_image_data"

    with pytest.raises(NotImplementedError):
        # Should raise until properly implemented
        await handler.create_newsletter(name, description, picture)

@pytest.mark.asyncio
async def test_newsletter_retrieval():
    """Test getting newsletter info."""
    handler = NewsletterHandler()
    newsletter_id = "newsletter-123"

    with pytest.raises(NotImplementedError):
        await handler.get_newsletter(newsletter_id)

@pytest.mark.asyncio
async def test_newsletter_update():
    """Test updating newsletter settings."""
    handler = NewsletterHandler()
    newsletter_id = "newsletter-123"
    new_name = "Updated Newsletter"

    with pytest.raises(NotImplementedError):
        await handler.update_newsletter(newsletter_id, name=new_name)

@pytest.mark.asyncio
async def test_newsletter_deletion():
    """Test deleting a newsletter."""
    handler = NewsletterHandler()
    newsletter_id = "newsletter-123"

    with pytest.raises(NotImplementedError):
        await handler.delete_newsletter(newsletter_id)

@pytest.mark.asyncio
async def test_newsletter_message():
    """Test sending newsletter message."""
    handler = NewsletterHandler()
    newsletter_id = "newsletter-123"

    message = WAMsgTransport_pb2.Message()
    message.conversation = "Test newsletter message"

    with pytest.raises(NotImplementedError):
        await handler.send_message(newsletter_id, message)

@pytest.mark.asyncio
async def test_newsletter_subscribers():
    """Test getting newsletter subscribers."""
    handler = NewsletterHandler()
    newsletter_id = "newsletter-123"

    with pytest.raises(NotImplementedError):
        await handler.get_subscribers(newsletter_id)
