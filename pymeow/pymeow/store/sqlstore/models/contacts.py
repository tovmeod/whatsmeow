from tortoise.models import Model
from tortoise import fields
from typing import Optional

class Contact(Model):
    """Contact information"""
    our_jid = fields.CharField(max_length=255)
    their_jid = fields.CharField(max_length=255)
    first_name = fields.CharField(max_length=255, null=True)
    full_name = fields.CharField(max_length=255, null=True)
    push_name = fields.CharField(max_length=255, null=True)
    business_name = fields.CharField(max_length=255, null=True)

    class Meta:
        table = "pymeow_contacts"
        unique_together = (("our_jid", "their_jid"),)
