from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from ..models import TestExecution, LLMAnalysis
from ..serializers.execution_serializers import (
    ExecutionListSerializer,
    ExecutionDetailSerializer,
    ExecutionCreateSerializer,
    RetryExecutionSerializer,
    LLMAnalysisSerializer
)
from ..tasks import execute_security_test_case, analyze_with_llm

class ExecutionViewSet(viewsets.ModelViewSet):
    queryset = TestExecution.objects.all().order_by('-executed_at')
    lookup_field = 'slug'

    def get_serializer_class(self):
        if self.action == 'list':
            return ExecutionListSerializer
        elif self.action == 'create':
            return ExecutionCreateSerializer
        elif self.action == 'retry':
            return RetryExecutionSerializer
        elif self.action == 'analysis':
            return LLMAnalysisSerializer
        return ExecutionDetailSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        execution = TestExecution(
            security_test_case=serializer.validated_data['security_test_case'],
            api_test=serializer.validated_data['security_test_case'].api_test,
            executed_by=request.user,
            custom_payload=serializer.validated_data.get('custom_payload', {})
        )
        execution.save()
        
        execute_security_test_case.delay(execution.id)
        
        return Response(
            ExecutionDetailSerializer(execution).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def retry(self, request, slug=None):
        execution = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        new_execution = TestExecution(
            api_test=execution.api_test,
            security_test_case=execution.security_test_case,
            executed_by=request.user,
            custom_payload=serializer.validated_data.get('payload_override', execution.custom_payload)
        )
        new_execution.save()
        
        execute_security_test_case.delay(new_execution.id)
        
        return Response({
            "status": "requeued",
            "new_execution_id": new_execution.id
        }, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def analysis(self, request, slug=None):
        execution = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        analysis = LLMAnalysis(
            execution=execution,
            **serializer.validated_data
        )
        analysis.save()
        
        analyze_with_llm.delay(analysis.id)
        
        return Response(
            {"status": "analysis_started", "analysis_id": analysis.id},
            status=status.HTTP_202_ACCEPTED
        )