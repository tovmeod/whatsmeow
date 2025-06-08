from tortoise.models import Model
from tortoise import fields
from typing import Optional

class DeviceModel(Model):
    """Device information storage"""
    id = fields.CharField(max_length=255, pk=True)
    registration_id = fields.IntField()
    signed_pre_key = fields.BinaryField()
    signed_pre_key_id = fields.IntField()
    signed_pre_key_signature = fields.BinaryField()
    identity_key_private = fields.BinaryField()
    identity_key_public = fields.BinaryField()
    phone_id = fields.CharField(max_length=255, null=True)
    device_id = fields.CharField(max_length=255, null=True)
    platform = fields.CharField(max_length=50, default="android")
    business_name = fields.CharField(max_length=255, null=True)
    push_name = fields.CharField(max_length=255, null=True)
    noise_key_private = fields.BinaryField(null=True)
    noise_key_public = fields.BinaryField(null=True)

    class Meta:
        table = "pymeow_device"
