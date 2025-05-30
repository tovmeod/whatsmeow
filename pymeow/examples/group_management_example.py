#!/usr/bin/env python3
"""
Group Management Example

This script demonstrates how to use PyMeow's group management features.
It shows how to create groups, manage participants, update settings, and more.
"""
import asyncio
import logging
from pprint import pprint

from pymeow import Client
from pymeow.auth import AuthState
from pymeow.exceptions import PymeowError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Replace with actual credentials or use QR code authentication
AUTH_STORAGE = "whatsapp_auth.json"

async def main():
    # Initialize the client
    client = Client()
    
    try:
        # Load authentication state or authenticate
        try:
            auth_state = AuthState.load(AUTH_STORAGE)
            await client.connect(auth_state)
        except FileNotFoundError:
            logger.info("No auth file found. Please scan the QR code to authenticate.")
            await client.connect()
            auth_state = client.auth_state
            auth_state.save(AUTH_STORAGE)
        
        logger.info("Connected to WhatsApp Web")
        
        # Example 1: Get list of joined groups
        logger.info("\n=== My Groups ===")
        groups = await client.get_joined_groups()
        for group in groups:
            print(f"- {group['subject']} ({group['id']})")
        
        # Example 2: Create a new group
        logger.info("\n=== Creating a New Group ===")
        try:
            # Replace with actual phone numbers in international format
            participants = [
                "1234567890@s.whatsapp.net",  # Replace with actual numbers
                "0987654321@s.whatsapp.net"   # Replace with actual numbers
            ]
            
            group = await client.create_group(
                subject="PyMeow Test Group",
                participants=participants
            )
            logger.info(f"Created group: {group['subject']} ({group['id']})")
            
            # Store group ID for later examples
            group_jid = group['id']
            
            # Example 3: Get group info
            logger.info("\n=== Group Info ===")
            group_info = await client.get_group_info(group_jid)
            print(f"Group Name: {group_info['subject']}")
            print(f"Created by: {group_info['creator']}")
            print(f"Participants: {len(group_info['participants'])}")
            
            # Example 4: Update group settings
            logger.info("\n=== Updating Group Settings ===")
            # Enable admin-only messages
            await client.set_group_setting(group_jid, "announcement", True)
            # Set disappearing messages to 1 day
            await client.set_group_setting(group_jid, "ephemeral", 86400)
            
            # Verify settings
            settings = await client.get_group_settings(group_jid)
            print("\nCurrent Group Settings:")
            pprint(settings)
            
            # Example 5: Get group invite link
            logger.info("\n=== Group Invite Link ===")
            invite_link = await client.get_group_invite_link(group_jid)
            print(f"Invite link: {invite_link}")
            
            # Example 6: Update group subject
            logger.info("\n=== Updating Group Subject ===")
            await client.set_group_subject(group_jid, "PyMeow Test Group - Updated")
            
            # Example 7: Manage participants
            logger.info("\n=== Managing Participants ===")
            # Replace with actual phone numbers
            new_participant = "1122334455@s.whatsapp.net"
            
            # Add a participant
            result = await client.update_group_participants(
                group_jid=group_jid,
                add_participants=[new_participant]
            )
            print(f"Added participants: {result.get('added', [])}")
            
            # Promote to admin
            if result.get('added'):
                admin_result = await client.set_group_admins(
                    group_jid=group_jid,
                    participant_jids=[new_participant],
                    promote=True
                )
                print(f"Promoted to admin: {admin_result.get('succeeded', [])}")
            
        except PymeowError as e:
            logger.error(f"Error in group operations: {e}")
        
        # Example 8: Leave the group (commented out for safety)
        # await client.leave_group(group_jid)
        # logger.info(f"Left group: {group_jid}")
        
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
    finally:
        # Save auth state before disconnecting
        if 'auth_state' in locals():
            auth_state.save(AUTH_STORAGE)
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
