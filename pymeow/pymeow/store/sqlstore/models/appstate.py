from tortoise import fields
from tortoise.models import Model


class AppStateSyncKeyModel(Model):
    """App state sync keys"""
    jid = fields.ForeignKeyField('models.DeviceModel', related_name='app_state_sync_keys', to_field='jid',
                                 on_delete=fields.CASCADE, on_update=fields.CASCADE)
    key_id = fields.BinaryField()
    key_data = fields.BinaryField()
    timestamp = fields.BigIntField()
    fingerprint = fields.BinaryField()

    class Meta:
        table = "pymeow_app_state_sync_keys"
        unique_together = (("jid", "key_id"),)

class AppStateVersionModel(Model):
    """App state versions"""
    jid = fields.ForeignKeyField('models.DeviceModel', related_name='app_state_versions', to_field='jid',
                                 on_delete=fields.CASCADE, on_update=fields.CASCADE)
    name = fields.CharField(max_length=255)
    version = fields.BigIntField()
    hash = fields.BinaryField()

    class Meta:
        table = "pymeow_app_state_version"
        unique_together = (("jid", "name"),)


class AppStateMutationMACModel(Model):
    """App state mutation MAC storage."""
    # Since Tortoise doesn't support composite foreign keys, we store the fields separately
    # but reference the device for the main cascade relationship
    jid = fields.ForeignKeyField('models.DeviceModel', related_name='mutation_macs', to_field='jid',
                                 on_delete=fields.CASCADE, on_update=fields.CASCADE)
    name = fields.CharField(max_length=255)
    version = fields.BigIntField()
    index_mac = fields.BinaryField()
    value_mac = fields.BinaryField()

    class Meta:
        table = "pymeow_app_state_mutation_macs"
        unique_together = (("jid", "name", "version", "index_mac"),)

