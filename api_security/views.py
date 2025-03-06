from django.shortcuts import render

from api_security.models import *
from rest_framework import permissions
from .serializers import *
from utils.custom_veinlet import CustomViewSet

# Create your views here.

class MITREAttackTacticViewSet(CustomViewSet):
    queryset = MITREAttackTactic.objects.all().order_by('-created_at')
    lookup_field = 'slug'
    serializer_class = MITREAttackTacticSerializer
    permission_classes = [permissions.AllowAny]
    
class MITREAttackTechniqueViewSet(CustomViewSet):
    queryset = MITREAttackTechnique.objects.all().order_by('-created_at')
    lookup_field = 'slug'
    serializer_class = MITREAttackTechniqueSerializer
    permission_classes = [permissions.AllowAny]