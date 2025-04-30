from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status, viewsets
from django.shortcuts import get_object_or_404

from api_scanner.serializers.test_serializers import APITestCreateUpdateSerializer, APITestDetailSerializer, APITestListSerializer, AttackSimulationSerializer
from api_scanner.serializers.log_serializers import APILogSerializer
from ..models import APITest, SecurityTestCase, TestExecution, APILog
from ..tasks import execute_api_test
from ..serializers.execution_serializers import TestExecutionSerializer

class APITestViewSet(viewsets.ModelViewSet):
    queryset = APITest.objects.all()
    lookup_field = 'slug'
    
    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return APITestCreateUpdateSerializer
        elif self.action == 'list':
            return APITestListSerializer
        elif self.action == 'retrieve':
            return APITestDetailSerializer
        elif self.action == 'simulate_attack':
            return AttackSimulationSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=['post'])
    def execute(self, request, slug=None):
        """
        POST /api/tests/{slug}/execute/
        Execute all test cases for this API
        """
        api_test = self.get_object()
        test_cases = SecurityTestCase.objects.filter(api_test=api_test)
        
        if not test_cases.exists():
            return Response(
                {"detail": "No test cases found for this API"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create execution records
        executions = []
        for test_case in test_cases:
            execution = TestExecution.objects.create(
                api_test=api_test,
                security_test_case=test_case,
                executed_by=request.user
            )
            executions.append(execution)
            # Trigger async execution
            execute_api_test.delay(execution.id)
        
        serializer = TestExecutionSerializer(executions, many=True)
        return Response(
            {
                "detail": f"Started execution of {len(executions)} test cases",
                "executions": serializer.data
            },
            status=status.HTTP_202_ACCEPTED
        )
        
    @action(detail=True, methods=['post'], serializer_class=AttackSimulationSerializer)
    def simulate_attack(self, request, slug=None):
        api_test = self.get_object()
        test_cases = api_test.security_test_cases.filter(severity__in=['High', 'Critical'])
        
        if not test_cases.exists():
            # Return available severities for debugging
            available = api_test.security_test_cases.values_list('severity', flat=True).distinct()
            return Response(
                {
                    "detail": "No high-severity test cases found",
                    "available_severities": list(available),
                    "suggestion": "Create test cases with High/Critical severity first"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        simulations = []
        for test_case in test_cases:
            simulations.append(
                AttackSimulation.objects.create(
                    api_test=api_test,
                    security_test_case=test_case,
                    executed_by=request.user
                )
            )
        
        return Response(
            self.get_serializer(simulations, many=True).data,
            status=status.HTTP_202_ACCEPTED
        )
        
    @action(detail=True, methods=['get'], url_path='logs')
    def logs(self, request, slug=None):
        """
        GET /api/tests/{slug}/logs/
        Retrieve logs for a specific API test
        """
        api_test = self.get_object()
        logs = APILog.objects.filter(api_test=api_test).order_by('-timestamp')
        
        # Pagination
        page = self.paginate_queryset(logs)
        if page is not None:
            serializer = APILogSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = APILogSerializer(logs, many=True)
        return Response(serializer.data)