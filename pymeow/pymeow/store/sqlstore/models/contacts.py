from tortoise import fields
from tortoise.models import Model


class ContactModel(Model):
    """Contact information"""

    our_jid: Optional[str] = fields.ForeignKeyField(  # type: ignore[assignment]
        "models.DeviceModel",
        related_name="contacts",
        to_field="jid",
        on_delete=fields.CASCADE,
        on_update=fields.CASCADE,
    )
    their_jid = fields.CharField(max_length=255)
    first_name = fields.CharField(max_length=255, null=True)
    full_name = fields.CharField(max_length=255, null=True)
    push_name = fields.CharField(max_length=255, null=True)
    business_name = fields.CharField(max_length=255, null=True)

    class Meta:
        table = "pymeow_contacts"
        unique_together = (("our_jid", "their_jid"),)
