from tortoise import fields
from tortoise.models import Model


class PrivacyTokenModel(Model):
    our_jid = fields.CharField(max_length=255)
    their_jid = fields.CharField(max_length=255)
    token = fields.BinaryField()
    timestamp = fields.BigIntField()

    class Meta:
        table = "pymeow_privacy_tokens"
        unique_together = (("our_jid", "their_jid"),)
