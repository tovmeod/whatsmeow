from tortoise.models import Model
from tortoise import fields


class IdentityKey(Model):
    """Identity key storage for Signal protocol"""
    our_jid = fields.CharField(max_length=255)
    their_id = fields.CharField(max_length=255)
    identity = fields.BinaryField()

    class Meta:
        table = "pymeow_identity_keys"
        unique_together = (("our_jid", "their_id"),)

class Session(Model):
    """Signal protocol sessions"""
    our_jid = fields.CharField(max_length=255)
    their_id = fields.CharField(max_length=255)
    session = fields.BinaryField()

    class Meta:
        table = "pymeow_sessions"
        unique_together = (("our_jid", "their_id"),)

class PreKeyModel(Model):
    """Pre-keys for Signal protocol"""
    jid = fields.CharField(max_length=255)
    key_id = fields.IntField()
    key = fields.BinaryField()
    uploaded = fields.BooleanField(default=False)

    class Meta:
        table = "pymeow_pre_keys"
        unique_together = (("jid", "key_id"),)

class SenderKey(Model):
    """Sender keys for group encryption"""
    our_jid = fields.CharField(max_length=255)
    chat_id = fields.CharField(max_length=255)
    sender_id = fields.CharField(max_length=255)
    sender_key = fields.BinaryField()

    class Meta:
        table = "pymeow_sender_keys"
        unique_together = (("our_jid", "chat_id", "sender_id"),)
