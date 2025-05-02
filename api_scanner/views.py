# views.py
from django.shortcuts import render
from api_scanner.models import *
from api_scanner.serializers import *
from utils.custom_veinlet import CustomViewSet
from rest_framework import permissions
from utils.calculation import *
from utils.decorators import log_activity
from utils.response_wrapper import ResponseWrapper
from utils.generates import unique_slug_generator
from utils.actions import send_action, activity_log
from utils.permissions import CheckCustomPermission

class APITestViewSet(CustomViewSet):
    queryset = APITest.objects.all().order_by('name')
    lookup_field = 'slug'
    serializer_class = APITestSerializer
    permission_classes = [permissions.IsAuthenticated]

    @log_activity
    def create(self, request, *args, **kwargs):
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.data, partial=True)
        
        if not serializer.is_valid():
            return ResponseWrapper(error_msg=serializer.errors, error_code=400)
            
        # Generate slug
        name = request.data.get('name')
        slug = unique_slug_generator(name=name) if name else None
        
        # Save instance
        serializer.validated_data['slug'] = slug
        serializer.validated_data['created_by'] = request.user
        qs = serializer.save()

        # Perform security analysis

        # Build response
        
        raw_endpoint = request.data.get('endpoint')
        request_meta = {
            'url': raw_endpoint,
            'method': request.method,
            'headers': request.headers,
            'body': request.data
        }
        
        detected_techniques = detect_mitre_patterns(qs)

        # 2. Analyze endpoint dynamics
        detector = DynamicEndpointDetector()
        normalized = detector.normalize_endpoint(raw_endpoint)
        params = detector.extract_parameters(raw_endpoint)

        # 3. Behavioral analysis
        profiler = APIBehaviorProfiler()
        analysis = profiler.analyze_request(request_meta)

        # 4. MITRE Technique Mapping
        mapper = MitreTechniqueMapper()
        mitre_findings = mapper.map_anomalies(analysis['anomalies'])
        
        
        response_data = {
            'normalized_endpoint': normalized,
            'parameter_analysis': params,
            'mitre_findings': mitre_findings,
            'risk_score': analysis['risk_score']
        }

        return ResponseWrapper(data=response_data, msg='created', status=200)