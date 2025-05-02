from rest_framework import serializers

from user.serializers import UserInformationBaseSerializer
from .models import *

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
    # def create(self, validated_data):
    #     user = self.context['request'].user
    #     validated_data['created_by'] = user
    #     return super(APITestSerializer, self).create(validated_data)
    
    # def update(self, instance, validated_data):
    #     user = self.context['request'].user
    #     validated_data['created_by'] = user
    #     return super(APITestSerializer, self).update(instance, validated_data)
    
    def to_representation(self, instance):
        self.fields["created_by"] = UserInformationBaseSerializer(read_only=True)
        return super(APITestSerializer, self).to_representation(instance)