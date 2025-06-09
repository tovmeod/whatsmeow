from tortoise import fields
from tortoise.models import Model

class LIDMappingModel(Model):
    lid = fields.CharField(max_length=255, pk=True)  # PRIMARY KEY
    pn = fields.CharField(max_length=255, unique=True)

    class Meta:
        table = "pymeow_lid_map"
