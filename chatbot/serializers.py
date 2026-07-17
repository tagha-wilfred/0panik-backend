from rest_framework import serializers
from .models import ScamCheck

class ScamCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScamCheck
        fields = [
            'id', 
            'submitted_text', 
            'verdict', 
            'reason', 
            'source', 
            'url_checked',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']

class ChatbotCheckSerializer(serializers.Serializer):
    text = serializers.CharField(
        required=True,
        max_length=5000,
        trim_whitespace=True
    )