from rest_framework import serializers
from ..models import APITest, MITREAttackTechnique, SecurityTestCase, TestExecution, AttackSimulation

# For basic CRUD operations
class APITestCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = APITest
        fields = ['name', 'endpoint', 'http_method', 'headers', 'body', 'auth_type', 'auth_credentials']
        extra_kwargs = {
            'auth_credentials': {'write_only': True}
        }

class APITestListSerializer(serializers.ModelSerializer):
    class Meta:
        model = APITest
        fields = ['id', 'slug', 'name', 'endpoint', 'http_method', 'auth_type', 'created_at']

class APITestDetailSerializer(APITestListSerializer):
    test_case_count = serializers.IntegerField(source='security_test_cases.count', read_only=True)
    last_executed = serializers.DateTimeField(source='test_executions.latest.executed_at', read_only=True)

    class Meta(APITestListSerializer.Meta):
        fields = APITestListSerializer.Meta.fields + ['test_case_count', 'last_executed']

# For attack simulation
class AttackSimulationSerializer(serializers.ModelSerializer):
    technique_name = serializers.CharField(source='security_test_case.mitre_attack_technique.name', read_only=True)
    
    class Meta:
        model = AttackSimulation
        fields = ['id', 'slug', 'technique_name', 'executed_at', 'success', 'impact_description']
        read_only_fields = fields
        
        
class MITREAttackTechniqueSerializer(serializers.ModelSerializer):
    class Meta:
        model = MITREAttackTechnique
        fields = ['slug', 'name', 'description']

class SecurityTestCaseListSerializer(serializers.ModelSerializer):
    technique = MITREAttackTechniqueSerializer(source='mitre_attack_technique')
    
    class Meta:
        model = SecurityTestCase
        fields = ['slug', 'name', 'severity', 'technique', 'created_at']

class SecurityTestCaseDetailSerializer(SecurityTestCaseListSerializer):
    class Meta(SecurityTestCaseListSerializer.Meta):
        fields = SecurityTestCaseListSerializer.Meta.fields + [
            'description', 'payload', 'expected_response'
        ]

class SecurityTestCaseCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityTestCase
        fields = [
            'name', 'description', 'mitre_attack_technique', 
            'severity', 'payload', 'expected_response'
        ]