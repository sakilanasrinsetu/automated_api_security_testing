from rest_framework import serializers

from user.serializers import UserInformationBaseSerializer
from .models import *

class MITREAttackTacticSerializer(serializers.ModelSerializer):
    class Meta:
        model = MITREAttackTactic
        fields = "__all__"
class MITREAttackTechniqueSerializer(serializers.ModelSerializer):
    class Meta:
        model = MITREAttackTechnique
        fields = "__all__"
        
    def to_representation(self, instance):
        self.fields["tactic"] = MITREAttackTacticSerializer(read_only=True)
        return super(MITREAttackTechniqueSerializer, self).to_representation(instance)\
            
class APITestSerializer(serializers.ModelSerializer):
    class Meta:
        model = APITest
        fields = [
            'id', 
            'name', 
            'slug',
            'endpoint',
            'http_method',
            'headers',
            'body',
            'auth_type',
            'auth_credentials',
            'created_by',
            'created_at',
            'updated_at'
            ]
        
        read_only_fields = [
            'id',
            'slug',
            'created_by',
            'created_at',
            'updated_at'
        ]
    
    def to_representation(self, instance):
        self.fields["created_by"] = UserInformationBaseSerializer(read_only=True)
        return super(APITestSerializer, self).to_representation(instance)
    
    
# class APITestExecuteSerializer(serializers.ModelSerializer):
    
    
class SecurityTestCaseCreateSerializer(serializers.ModelSerializer):
    api_test = serializers.SlugRelatedField(
        queryset=APITest.objects.all(),
        slug_field='slug'
    )
    
    class Meta: 
        model = SecurityTestCase
        fields = [
            'api_test',
        ]
class SecurityTestCaseSerializer(serializers.ModelSerializer):
    mitre_attack_technique = serializers.SlugRelatedField(
        queryset=MITREAttackTechnique.objects.all(),
        slug_field='mitre_attack_technique_id'
    )
    api_test = serializers.SlugRelatedField(
        queryset=APITest.objects.all(),
        slug_field='slug'
    )

    class Meta:
        model = SecurityTestCase
        fields = [
            'id', 
            'name', 
            'slug',
            'description',
            'mitre_attack_technique',
            'api_test',
            'severity',
            'payload',
            'expected_response',
            'created_at',
            'updated_at'
        ]
        
        read_only_fields = [
            'id',
            'slug',
            'created_at',
            'updated_at'
        ]
    
    def to_representation(self, instance):
        # If you want to use a serializer for the related field
        self.fields["mitre_attack_technique"] = MITREAttackTechniqueSerializer(read_only=True)
        self.fields["api_test"] = APITestSerializer(read_only=True)
        return super().to_representation(instance)
 
    
    
    
class TestExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestExecution
        fields = "__all__"
        
    def to_representation(self, instance):
        self.fields["api_test"] = APITestSerializer(read_only=True)
        self.fields["security_test_case"] = SecurityTestCaseSerializer(read_only=True)
        self.fields["executed_by"] = UserInformationBaseSerializer(read_only=True)
        return super(TestExecutionSerializer, self).to_representation(instance)

class LLMAnalysisSerializer(serializers.ModelSerializer):
    test_execution = serializers.SlugRelatedField(
        queryset=TestExecution.objects.all(),
        slug_field='slug'
    )
    class Meta:
        model = LLMAnalysis
        fields = "__all__"
        
    def to_representation(self, instance):
        self.fields["test_execution"] = TestExecutionSerializer(read_only=True)
        return super(LLMAnalysisSerializer, self).to_representation(instance)
    
    
    
class AttackSimulationSerializer(serializers.ModelSerializer):
    api_test = serializers.SlugRelatedField(
        queryset=APITest.objects.all(),
        slug_field='slug'
    )
    security_test_case = serializers.SlugRelatedField(
        queryset=SecurityTestCase.objects.all(),
        slug_field='slug'
    )
    class Meta:
        model = AttackSimulation
        fields = [
            'slug', 
            'api_test', 
            'security_test_case',
             'executed_by',
             'impact_description',
             'success']
        
        read_only_fields = [
            'slug', 
            'executed_by', 
            'created_at', 
            'updated_at'
            ]

    def to_representation(self, instance):
        self.fields["api_test"] = APITestSerializer(read_only=True)
        self.fields["security_test_case"] = SecurityTestCaseSerializer(read_only=True)
        self.fields["executed_by"] = UserInformationBaseSerializer(read_only=True)
        return super(AttackSimulationSerializer, self).to_representation(instance)
    
    
class ReportSerializer(serializers.ModelSerializer):
    test_execution = serializers.SlugRelatedField(
        queryset=TestExecution.objects.all(),
        slug_field='slug'
    )
    class Meta:
        model = Report
        fields = "__all__"
        
    def to_representation(self, instance):
        self.fields["test_execution"] = TestExecutionSerializer(read_only=True)
        return super(ReportSerializer, self).to_representation(instance)
    
    
class APILogSerializer(serializers.ModelSerializer):
    api_test = serializers.SlugRelatedField(
        queryset=APITest.objects.all(),
        slug_field='slug'
    )
    
    class Meta:
        model = APILog
        fields = "__all__"
        
    def to_representation(self, instance):
        self.fields["api_test"] = APITestSerializer(read_only=True)
        self.fields["attempted_by"] = UserInformationBaseSerializer(read_only=True)
        return super(APILogSerializer, self).to_representation(instance)