from tortoise.models import Model
from tortoise import fields


# todo rename to AppStateSyncKeyModel
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

# todo rename to AppStateVersionModel
class AppStateVersion(Model):
    """App state versions"""
    jid = fields.CharField(max_length=255)
    name = fields.CharField(max_length=255)
    version = fields.BigIntField()
    hash = fields.BinaryField()

    class Meta:
        table = "pymeow_app_state_version"
        unique_together = (("jid", "name"),)

class AppStateMutationMACModel(Model):
    """App state mutation MAC storage."""

    class Meta:
        table = "whatsmeow_app_state_mutation_macs"
        unique_together = (("jid", "name", "index_mac"),)  # Based on Go queries

    id = fields.IntField(pk=True)
    jid = fields.CharField(max_length=255)
    name = fields.CharField(max_length=255)
    version = fields.BigIntField()
    index_mac = fields.BinaryField()
    value_mac = fields.BinaryField()
