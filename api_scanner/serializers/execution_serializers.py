from rest_framework import serializers
from api_scanner.models import TestExecution

class TestExecutionResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestExecution
        fields = '__all__'
        read_only_fields = fields
