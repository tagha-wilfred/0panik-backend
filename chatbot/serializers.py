from rest_framework import serializers
from .models import ScamCheck

class ScamCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScamCheck
        fields = ['id', 'submitted_text', 'verdict', 'reason', 'source', 'created_at']
        read_only_fields = ['id', 'created_at']