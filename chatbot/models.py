import uuid
from django.db import models
from django.conf import settings

class ScamCheck(models.Model):
    VERDICT_CHOICES = [
        ('safe', 'Safe'),
        ('risky', 'Risky'),
        ('unknown', 'Unknown'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scam_checks')
    submitted_text = models.TextField()
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    reason = models.TextField(blank=True, null=True)
    source = models.CharField(max_length=50)  # e.g., 'safe_browsing', 'heuristic', 'combined'
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.verdict} at {self.created_at}"