from tortoise import fields
from tortoise.models import Model

class ChatSettingsModel(Model):
    our_jid = fields.ForeignKeyField('models.DeviceModel', related_name='chat_settings', to_field='jid',
                                     on_delete=fields.CASCADE, on_update=fields.CASCADE)
    chat_jid = fields.CharField(max_length=255)
    muted_until = fields.BigIntField(default=0)
    pinned = fields.BooleanField(default=False)
    archived = fields.BooleanField(default=False)

    class Meta:
        table = "pymeow_chat_settings"
        unique_together = (("our_jid", "chat_jid"),)
