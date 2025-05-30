"""
Tests for the JID class.
"""
import unittest
from pymeow.pymeow.types.jid import (
    JID, DEFAULT_USER_SERVER, GROUP_SERVER, BROADCAST_SERVER, NEWSLETTER_SERVER,
    LEGACY_USER_SERVER, BOT_SERVER, EMPTY_JID, STATUS_BROADCAST_JID
)


class TestJID(unittest.TestCase):
    """Test cases for the JID class."""

    def test_create_jid(self):
        """Test creating a JID."""
        jid = JID(user="1234567890", server=DEFAULT_USER_SERVER)
        self.assertEqual(jid.user, "1234567890")
        self.assertEqual(jid.server, DEFAULT_USER_SERVER)
        self.assertEqual(jid.raw_agent, 0)
        self.assertEqual(jid.device, 0)
        self.assertEqual(jid.integrator, 0)

    def test_create_ad_jid(self):
        """Test creating an AD JID."""
        jid = JID.new_ad_jid("1234567890", 0, 1)
        self.assertEqual(jid.user, "1234567890")
        self.assertEqual(jid.server, DEFAULT_USER_SERVER)
        self.assertEqual(jid.raw_agent, 0)
        self.assertEqual(jid.device, 1)
        self.assertEqual(jid.integrator, 0)

    def test_string_representation(self):
        """Test string representation of JIDs."""
        jid1 = JID(user="1234567890", server=DEFAULT_USER_SERVER)
        self.assertEqual(str(jid1), "1234567890@s.whatsapp.net")

        jid2 = JID(user="1234567890", server=DEFAULT_USER_SERVER, device=1)
        self.assertEqual(str(jid2), "1234567890:1@s.whatsapp.net")

        jid3 = JID(user="1234567890", server=DEFAULT_USER_SERVER, raw_agent=2, device=1)
        self.assertEqual(str(jid3), "1234567890.2:1@s.whatsapp.net")

        jid4 = JID(user="", server=GROUP_SERVER)
        self.assertEqual(str(jid4), "g.us")

    def test_parse_jid(self):
        """Test parsing JIDs from strings."""
        jid1, error1 = JID.parse_jid("1234567890@s.whatsapp.net")
        self.assertIsNone(error1)
        self.assertEqual(jid1.user, "1234567890")
        self.assertEqual(jid1.server, DEFAULT_USER_SERVER)

        jid2, error2 = JID.parse_jid("1234567890:1@s.whatsapp.net")
        self.assertIsNone(error2)
        self.assertEqual(jid2.user, "1234567890")
        self.assertEqual(jid2.server, DEFAULT_USER_SERVER)
        self.assertEqual(jid2.device, 1)

        jid3, error3 = JID.parse_jid("1234567890.2:1@s.whatsapp.net")
        self.assertIsNone(error3)
        self.assertEqual(jid3.user, "1234567890")
        self.assertEqual(jid3.server, DEFAULT_USER_SERVER)
        self.assertEqual(jid3.raw_agent, 2)
        self.assertEqual(jid3.device, 1)

        jid4, error4 = JID.parse_jid("g.us")
        self.assertIsNone(error4)
        self.assertEqual(jid4.user, "")
        self.assertEqual(jid4.server, GROUP_SERVER)

    def test_from_string(self):
        """Test creating JIDs from strings."""
        jid1 = JID.from_string("1234567890@s.whatsapp.net")
        self.assertEqual(jid1.user, "1234567890")
        self.assertEqual(jid1.server, DEFAULT_USER_SERVER)

        jid2 = JID.from_string("1234567890:1@s.whatsapp.net")
        self.assertEqual(jid2.user, "1234567890")
        self.assertEqual(jid2.server, DEFAULT_USER_SERVER)
        self.assertEqual(jid2.device, 1)

        jid3 = JID.from_string("1234567890.2:1@s.whatsapp.net")
        self.assertEqual(jid3.user, "1234567890")
        self.assertEqual(jid3.server, DEFAULT_USER_SERVER)
        self.assertEqual(jid3.raw_agent, 2)
        self.assertEqual(jid3.device, 1)

        jid4 = JID.from_string("g.us")
        self.assertEqual(jid4.user, "")
        self.assertEqual(jid4.server, GROUP_SERVER)

        # Test with None
        self.assertIsNone(JID.from_string(None))

        # Test with existing JID
        jid5 = JID(user="test", server="test.com")
        self.assertEqual(JID.from_string(jid5), jid5)

    def test_jid_types(self):
        """Test JID type checking methods."""
        user_jid = JID(user="1234567890", server=DEFAULT_USER_SERVER)
        self.assertTrue(user_jid.is_user())
        self.assertFalse(user_jid.is_group())
        self.assertFalse(user_jid.is_broadcast())
        self.assertFalse(user_jid.is_status_broadcast())
        self.assertFalse(user_jid.is_newsletter())

        group_jid = JID(user="1234567890", server=GROUP_SERVER)
        self.assertFalse(group_jid.is_user())
        self.assertTrue(group_jid.is_group())
        self.assertFalse(group_jid.is_broadcast())
        self.assertFalse(group_jid.is_status_broadcast())
        self.assertFalse(group_jid.is_newsletter())

        broadcast_jid = JID(user="1234567890", server=BROADCAST_SERVER)
        self.assertFalse(broadcast_jid.is_user())
        self.assertFalse(broadcast_jid.is_group())
        self.assertTrue(broadcast_jid.is_broadcast())
        self.assertFalse(broadcast_jid.is_status_broadcast())
        self.assertFalse(broadcast_jid.is_newsletter())

        status_broadcast_jid = STATUS_BROADCAST_JID
        self.assertFalse(status_broadcast_jid.is_user())
        self.assertFalse(status_broadcast_jid.is_group())
        self.assertTrue(status_broadcast_jid.is_broadcast())
        self.assertTrue(status_broadcast_jid.is_status_broadcast())
        self.assertFalse(status_broadcast_jid.is_newsletter())

        newsletter_jid = JID(user="1234567890", server=NEWSLETTER_SERVER)
        self.assertFalse(newsletter_jid.is_user())
        self.assertFalse(newsletter_jid.is_group())
        self.assertFalse(newsletter_jid.is_broadcast())
        self.assertFalse(newsletter_jid.is_status_broadcast())
        self.assertTrue(newsletter_jid.is_newsletter())

    def test_to_non_ad(self):
        """Test converting to non-AD JID."""
        jid = JID(user="1234567890", server=DEFAULT_USER_SERVER, raw_agent=2, device=1)
        non_ad_jid = jid.to_non_ad()
        self.assertEqual(non_ad_jid.user, "1234567890")
        self.assertEqual(non_ad_jid.server, DEFAULT_USER_SERVER)
        self.assertEqual(non_ad_jid.raw_agent, 0)
        self.assertEqual(non_ad_jid.device, 0)

    def test_equality(self):
        """Test JID equality."""
        jid1 = JID(user="1234567890", server=DEFAULT_USER_SERVER)
        jid2 = JID(user="1234567890", server=DEFAULT_USER_SERVER)
        jid3 = JID(user="0987654321", server=DEFAULT_USER_SERVER)
        jid4 = JID(user="1234567890", server=GROUP_SERVER)
        jid5 = JID(user="1234567890", server=DEFAULT_USER_SERVER, device=1)

        self.assertEqual(jid1, jid2)
        self.assertNotEqual(jid1, jid3)
        self.assertNotEqual(jid1, jid4)
        self.assertNotEqual(jid1, jid5)
        self.assertNotEqual(jid1, "not a jid")

    def test_is_empty(self):
        """Test is_empty method."""
        self.assertTrue(EMPTY_JID.is_empty())
        self.assertFalse(JID(user="1234567890", server=DEFAULT_USER_SERVER).is_empty())

    def test_is_bot(self):
        """Test is_bot method."""
        bot_jid1 = JID(user="13135550001", server=DEFAULT_USER_SERVER)
        bot_jid2 = JID(user="1234567890", server=BOT_SERVER)
        not_bot_jid = JID(user="1234567890", server=DEFAULT_USER_SERVER)

        self.assertTrue(bot_jid1.is_bot())
        self.assertTrue(bot_jid2.is_bot())
        self.assertFalse(not_bot_jid.is_bot())


if __name__ == "__main__":
    unittest.main()
