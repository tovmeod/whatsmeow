from tortoise import fields
from tortoise.models import Model

class MessageSecretModel(Model):
    our_jid = fields.ForeignKeyField('models.DeviceModel', related_name='message_secrets', to_field='jid', on_delete=fields.CASCADE, on_update=fields.CASCADE)
    chat_jid = fields.CharField(max_length=255)
    sender_jid = fields.CharField(max_length=255)
    message_id = fields.CharField(max_length=255)
    key = fields.BinaryField()

    class Meta:
        table = "pymeow_message_secrets"
        unique_together = (("our_jid", "chat_jid", "sender_jid", "message_id"),)
