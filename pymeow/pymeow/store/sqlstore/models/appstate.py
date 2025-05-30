from tortoise.models import Model
from tortoise import fields


class AppStateSyncKey(Model):
    """App state sync keys"""
    jid = fields.CharField(max_length=255)
    key_id = fields.BinaryField()
    key_data = fields.BinaryField()
    timestamp = fields.BigIntField()
    fingerprint = fields.BinaryField()

    class Meta:
        table = "pymeow_app_state_sync_keys"
        unique_together = (("jid", "key_id"),)

class AppStateVersion(Model):
    """App state versions"""
    jid = fields.CharField(max_length=255)
    name = fields.CharField(max_length=255)
    version = fields.BigIntField()
    hash = fields.BinaryField()

    class Meta:
        table = "pymeow_app_state_version"
        unique_together = (("jid", "name"),)
