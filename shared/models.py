from django.db import models
import uuid

class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, unique= True, default=uuid.uuid4, editable=False)
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


