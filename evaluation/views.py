from rest_framework.views import APIView
from rest_framework.response import Response
from evaluation.models import *
from evaluation.serializers import *
from django.db import transaction
from utils.permissions import IsAuthenticated

from utils.custom_veinlet import CustomViewSet
from utils.response_wrapper import ResponseWrapper
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, viewsets, filters

from utils.decorators import log_activity
from utils.generates import unique_slug_generator


class GroundTruthVulnerabilityViewSet(CustomViewSet):
    queryset = GroundTruthVulnerability.objects.all()
    serializer_class = GroundTruthVulnerabilitySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'slug'
    
    
    