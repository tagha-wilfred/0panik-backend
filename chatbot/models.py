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
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='scam_checks'
    )
    submitted_text = models.TextField()
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    reason = models.TextField(blank=True, null=True)
    source = models.CharField(max_length=50)  # 'safe_browsing', 'heuristic', 'combined'
    url_checked = models.URLField(max_length=500, blank=True, null=True)  # Track which URL was checked
    safe_browsing_response = models.JSONField(blank=True, null=True)  # Store raw response for debugging
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.verdict} at {self.created_at}"