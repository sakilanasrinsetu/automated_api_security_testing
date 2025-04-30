from rest_framework import serializers
from ..models import AttackSimulation

class AttackSimulationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackSimulation
        fields = [
            'id', 'slug', 'api_test', 'security_test_case',
            'executed_by', 'executed_at', 'success',
            'impact_description', 'created_at'
        ]
        read_only_fields = fields  # All fields are read-only