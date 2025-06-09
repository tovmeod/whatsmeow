from tortoise.models import Model
from tortoise import fields

class DeviceModel(Model):
    """Device information storage"""
    jid = fields.CharField(max_length=255, pk=True)
    lid = fields.CharField(max_length=255, null=True)
    facebook_uuid = fields.UUIDField(null=True)

    registration_id = fields.BigIntField()

    noise_key = fields.BinaryField()
    identity_key = fields.BinaryField()

    signed_pre_key = fields.BinaryField()
    signed_pre_key_id = fields.IntField()
    signed_pre_key_sig = fields.BinaryField()

    adv_key = fields.BinaryField()
    adv_details = fields.BinaryField()
    adv_account_sig = fields.BinaryField()
    adv_account_sig_key = fields.BinaryField()
    adv_device_sig = fields.BinaryField()

    platform = fields.CharField(max_length=50, default="")
    business_name = fields.CharField(max_length=255, default="")
    push_name = fields.CharField(max_length=255, default="")

    class Meta:
        table = "pymeow_device"
