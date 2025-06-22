from tortoise import fields
from tortoise.models import Model
from typing import Optional


class BufferedEventModel(Model):
    our_jid: Optional[str] = fields.ForeignKeyField(  # type: ignore[assignment]
        "models.DeviceModel",
        related_name="buffered_events",
        to_field="jid",
        on_delete=fields.CASCADE,
        on_update=fields.CASCADE,
    )
    ciphertext_hash = fields.BinaryField()
    plaintext = fields.BinaryField(null=True)
    server_timestamp = fields.BigIntField()
    insert_timestamp = fields.BigIntField()

    class Meta:
        table = "pymeow_event_buffer"
        unique_together = (("our_jid", "ciphertext_hash"),)
