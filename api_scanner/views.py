from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from api_scanner.models import APITest
from utils.calculation import detect_mitre_patterns, calculate_vulnerability_score, serialize_mitre_data
from django.db import transaction

class APITestCreateView(APIView):
    @transaction.atomic
    def post(self, request):
        # 1. Validate and create APITest
        api_test = APITest.objects.create(
            name=request.data['name'],
            endpoint=request.data['endpoint'],
            http_method=request.data['http_method'],
            headers=request.data.get('headers', {}),
            body=request.data.get('body', {}),
            auth_type=request.data['auth_type'],
            auth_credentials=request.data.get('auth_credentials', ''),
            created_by=request.user
        )

        # 2. Analyze for MITRE ATT&CK patterns
        detected_techniques = detect_mitre_patterns(api_test)
        
        # 3. Calculate vulnerability score
        vuln_percentage = calculate_vulnerability_score(detected_techniques)

        # 4. Prepare the response
        response_data = {
            "api_test": {
                "id": str(api_test.id),
                "name": api_test.name,
                "endpoint": api_test.endpoint
            },
            "mitre_analysis": serialize_mitre_data(detected_techniques) | {
                "vulnerability_percentage": vuln_percentage
            }
        }

        return Response(response_data)
