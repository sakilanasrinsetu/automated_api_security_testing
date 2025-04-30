from rest_framework import generics, permissions
from api_scanner.models import APITest
from api_scanner.serializers.test_serializers import APITestSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.shortcuts import get_object_or_404

from api_scanner.models import APITest, SecurityTestCase, TestExecution
from api_scanner.serializers.execution_serializers import TestExecutionResultSerializer

import requests

# List & Create
class APITestListCreateView(generics.ListCreateAPIView):
    queryset = APITest.objects.all().order_by('-created_at')
    serializer_class = APITestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

# Retrieve, Update, Delete
class APITestDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = APITest.objects.all()
    serializer_class = APITestSerializer
    lookup_field = 'slug'
    permission_classes = [permissions.IsAuthenticated]


class ExecuteAllTestCasesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, slug):
        api_test = get_object_or_404(APITest, slug=slug)
        test_cases = SecurityTestCase.objects.filter(api_test=api_test)

        if not test_cases.exists():
            return Response({"detail": "No test cases found for this API test."},
                            status=status.HTTP_404_NOT_FOUND)

        results = []

        for case in test_cases:
            try:
                # Prepare the modified request based on the test case
                payload = api_test.body or {}
                injection_point = case.injection_point  # e.g., 'username' or 'email'
                if injection_point in payload:
                    payload[injection_point] = case.payload

                response = requests.request(
                    method=api_test.http_method,
                    url=api_test.endpoint,
                    headers=api_test.headers or {},
                    json=payload if api_test.http_method in ["POST", "PUT", "PATCH"] else None,
                    params=payload if api_test.http_method == "GET" else None
                )

                result = TestExecution.objects.create(
                    api_test=api_test,
                    test_case=case,
                    status_code=response.status_code,
                    response_text=response.text,
                    executed_by=request.user
                )

                results.append(result)

            except Exception as e:
                results.append({
                    "error": str(e),
                    "test_case_id": case.id
                })

        serialized = TestExecutionResultSerializer(results, many=True)
        return Response(serialized.data, status=status.HTTP_200_OK)