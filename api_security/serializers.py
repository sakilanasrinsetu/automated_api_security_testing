from rest_framework import serializers

from user.serializers import UserDetailsSerializer
from .models import *

class MITREAttackTacticSerializer(serializers.ModelSerializer):
    class Meta:
        model = MITREAttackTactic
        fields = [
                'id',
                'name',
                'slug',
                'description',
                'created_at' 
                ]
        
        read_only_fields = ['slug']
        
class MITREAttackTechniqueSerializer(serializers.ModelSerializer):
    tactic = serializers.SlugRelatedField(slug_field='slug', queryset=MITREAttackTactic.objects.all())
    class Meta:
        model = MITREAttackTechnique
        fields = [
                'id',
                'name',
                'slug',
                'description',
                'created_at' ,
                'tactic'
                ]
        
        read_only_fields = ['slug']
        
    def to_representation(self, instance):
        self.fields["tactic"] = MITREAttackTacticSerializer(read_only=True) 
        return super().to_representation(instance)
        
class APITestSerializer(serializers.ModelSerializer): 
    http_method_display = serializers.CharField(source = 'get_http_method_display', read_only=True)
    class Meta:
        model = APITest
        fields = "__all__"
        
        read_only_fields = [
            'slug',
            'http_method',
            'created_by',
            'updated_by',
            'auth_type',
            ]
        
    def to_representation(self, instance):
        self.fields["created_by"] = UserDetailsSerializer(read_only=True) 
        return super().to_representation(instance)
        
class SecurityTestCaseSerializer(serializers.ModelSerializer): 
    choices_display = serializers.CharField(source = 'get_choices_display', read_only=True)
    mitre_attack_technique = serializers.SlugRelatedField(slug_field='slug', queryset=MITREAttackTechnique.objects.all())
    class Meta:
        model = SecurityTestCase
        fields = "__all__"
        
        read_only_fields = [
            'slug',
            'choices',
            ]
        
    def to_representation(self, instance):
        self.fields["mitre_attack_technique"] = MITREAttackTacticSerializer(read_only=True) 
        return super().to_representation(instance)