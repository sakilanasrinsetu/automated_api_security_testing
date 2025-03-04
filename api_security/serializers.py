from rest_framework import serializers
from .models import *

class MITREAttackTacticSerializer(serializers.ModelSerializer):
    class Meta:
        model = MITREAttackTactic
        fields = '__all__'