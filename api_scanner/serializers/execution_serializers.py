from rest_framework import serializers
from ..models import TestExecution, LLMAnalysis

class TestExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestExecution
        fields = [
            'id', 'slug', 'api_test', 'security_test_case', 
            'status_code', 'success', 'executed_at'
        ]
        read_only_fields = fields  # All fields are read-only
        
        
class ExecutionListSerializer(serializers.ModelSerializer):
    api_test_name = serializers.CharField(source='api_test.name')
    test_case_name = serializers.CharField(source='security_test_case.name')
    
    class Meta:
        model = TestExecution
        fields = [
            'slug', 'status', 'executed_at', 
            'api_test_name', 'test_case_name', 'success'
        ]

class ExecutionDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestExecution
        fields = '__all__'
        
        # read_only_fields = fields

class ExecutionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestExecution
        fields = ['security_test_case', 'custom_payload']
        extra_kwargs = {
            'security_test_case': {'required': True}
        }

class RetryExecutionSerializer(serializers.Serializer):
    payload_override = serializers.JSONField(required=False)

class LLMAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = LLMAnalysis
        fields = ['analysis_result', 'risk_score', 'mitigation_suggestions']