from rest_framework import serializers
from ..models import TestExecution

class TestExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestExecution
        fields = [
            'id', 'slug', 'api_test', 'security_test_case', 
            'status_code', 'success', 'executed_at'
        ]
        read_only_fields = fields  # All fields are read-only