from rest_framework import serializers
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