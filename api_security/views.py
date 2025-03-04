from django.shortcuts import render

from api_security.models import *
from rest_framework import permissions
from .serializers import *
from utils.custom_veinlet import CustomViewSet

# Create your views here.

class MITREAttackTacticViewSet(CustomViewSet):
    queryset = MITREAttackTactic.objects.all()
    lookup_field = 'pk'
    serializer_class = MITREAttackTacticSerializer
    permission_classes = [permissions.AllowAny]