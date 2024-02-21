from django.db import models

# Create your models here.

class BaseModel(models.Model):
    id = models.UUIDField(unique=True, editable=False, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True