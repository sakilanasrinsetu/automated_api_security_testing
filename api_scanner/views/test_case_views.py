from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from ..models import SecurityTestCase, TestExecution
from ..serializers.test_serializers import (
    SecurityTestCaseListSerializer,
    SecurityTestCaseDetailSerializer,
    SecurityTestCaseCreateUpdateSerializer
)
from ..tasks import execute_security_test_case

class SecurityTestCaseViewSet(viewsets.ModelViewSet):
    queryset = SecurityTestCase.objects.all().order_by('-created_at')
    lookup_field = 'slug'

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return SecurityTestCaseCreateUpdateSerializer
        elif self.action == 'retrieve':
            return SecurityTestCaseDetailSerializer
        return SecurityTestCaseListSerializer

    @action(detail=True, methods=['post'])
    def execute(self, request, slug=None):
        test_case = self.get_object()
        
        # Ensure we have the related API test
        if not hasattr(test_case, 'api_test'):
            return Response(
                {"error": "No API test associated with this test case"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        execution = TestExecution(
            api_test=test_case.api_test,  # Explicitly set the foreign key
            security_test_case=test_case,
            executed_by=request.user,
            status='queued',
            response_body={},
            execution_parameters=request.data.get('overrides', {})
        )
        execution.save()
        
        execute_security_test_case.delay(execution.id)
        
        return Response({
            "status": "queued",
            "execution_id": execution.id,
            "monitor_url": reverse('execution-detail', kwargs={'slug': execution.slug})
        }, status=status.HTTP_202_ACCEPTED)
        
        