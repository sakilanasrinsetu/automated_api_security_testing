from rest_framework import serializers
from api_scanner.models import APITest

class APITestSerializer(serializers.ModelSerializer):
    class Meta:
        model = APITest
        fields = [
            'id', 'name', 'slug', 'endpoint', 'http_method',
            'headers', 'body', 'auth_type', 'auth_credentials',
            'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_by', 'created_at', 'updated_at']
