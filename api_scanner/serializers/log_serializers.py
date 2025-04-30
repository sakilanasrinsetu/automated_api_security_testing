from rest_framework import serializers
from ..models import APILog

class APILogSerializer(serializers.ModelSerializer):
    class Meta:
        model = APILog
        fields = [
            'id',
            'timestamp',
            'ip_address',
            'user_agent',
            'status',
            'response_code',
            'attempted_by_email'
        ]
        read_only_fields = fields

    attempted_by_email = serializers.EmailField(source='attempted_by.email', read_only=True)