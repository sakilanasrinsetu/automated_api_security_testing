from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from user.models import UserAccount


class RegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserAccount
        fields = [
            'email',
            'phone',
            'password',
            ]
        
class UserProfileUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserAccount
        fields = [
            'first_name',
            'last_name',
            'password',
            ]

class LoginSerializer(serializers.ModelSerializer):
    token = serializers.SerializerMethodField()
    class Meta:
        model = UserAccount
        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'is_superuser',
            'is_staff',
            'is_active',
            'date_joined',
            'last_login',
            'token',
            ]

    def get_token(self, obj):
        token = RefreshToken.for_user(obj)
        context = {
            'access_token': str(token.access_token),
            'refresh_token': str(token)
        }
        return context
    
class UserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = [
            'id',
            'first_name',
            'last_name',
            'email',
            'is_superuser',
            'is_staff',
            'is_active',
            'date_joined',
            'last_login',
            ]
        
class UserInformationBaseSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only = True)
    class Meta:
        model = UserAccount
        fields = [
                    'id',    
                    'name',
                    'email',  
                    'phone', 
                ]
        
    def get_name(self, obj):
        if obj.first_name or obj.last_name:
            return f"{obj.first_name} {obj.last_name}".strip()
        return '----'