import uuid
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator

class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    serial_number = models.CharField(max_length=64, unique=True)
    api_key = models.CharField(max_length=128, unique=True, blank=True)  # auto-generated on save
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='devices'
    )
    nickname = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    battery_level = models.IntegerField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(100)])
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.api_key:
            import secrets
            self.api_key = secrets.token_urlsafe(32)  # 32 bytes of entropy
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.serial_number} ({self.owner.email if self.owner else 'unclaimed'})"

class LocationPing(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='locations')
    latitude = models.DecimalField(max_digits=9, decimal_places=6, validators=[MinValueValidator(-90), MaxValueValidator(90)])
    longitude = models.DecimalField(max_digits=9, decimal_places=6, validators=[MinValueValidator(-180), MaxValueValidator(180)])
    battery_level = models.IntegerField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(100)])
    recorded_at = models.DateTimeField()  # device timestamp
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', '-recorded_at']),
        ]
        ordering = ['-recorded_at']