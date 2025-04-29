from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from api_scanner.models import TestExecution, APITest, SecurityTestCase
from api_scanner.serializers.report_serializers import TestExecutionSerializer

class TestExecutionViewSet(viewsets.ModelViewSet):
    """
    API endpoint to create, list, and retrieve Test Executions
    """
    queryset = TestExecution.objects.all().order_by('-executed_at')
    serializer_class = TestExecutionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(executed_by=self.request.user)
