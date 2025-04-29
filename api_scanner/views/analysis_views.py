from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from api_scanner.models import LLMAnalysis
from api_scanner.serializers.mitre_serializers import LLMAnalysisSerializer

class LLMAnalysisViewSet(viewsets.ModelViewSet):
    """
    API endpoint to manage LLM analysis for test executions
    """
    queryset = LLMAnalysis.objects.all().order_by('-created_at')
    serializer_class = LLMAnalysisSerializer
    permission_classes = [IsAuthenticated]
