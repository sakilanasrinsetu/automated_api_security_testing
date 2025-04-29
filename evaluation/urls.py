from django.urls import path
from evaluation.views import (
    EvaluationMetricViewSet,
    GroundTruthVulnerabilityViewSet,
    DetectionResultViewSet,
)

urlpatterns = [
    # GroundTruthVulnerability endpoints
    path('ground_truth_vulnerability/', 
         GroundTruthVulnerabilityViewSet.as_view({'get': 'list', 'post': 'create'}, name='ground_truth_vulnerability')),
    path('ground_truth_vulnerability/<pk>/', 
         GroundTruthVulnerabilityViewSet.as_view({'delete': 'destroy', 'patch': 'update', 'get': 'retrieve'},
                                                  name='ground_truth_vulnerability')),

    # DetectionResult endpoints
    path('detection_result/', 
         DetectionResultViewSet.as_view({'get': 'list', 'post': 'create'}, name='detection_result')),
    path('detection_result/<pk>/', 
         DetectionResultViewSet.as_view({'delete': 'destroy', 'patch': 'update', 'get': 'retrieve'},
                                        name='detection_result')),

    # EvaluationMetric endpoints
    path('evaluation_metric/', 
         EvaluationMetricViewSet.as_view({'get': 'list', 'post': 'create'}, name='evaluation_metric')),
    path('evaluation_metric/<pk>/', 
         EvaluationMetricViewSet.as_view({'delete': 'destroy', 'patch': 'update', 'get': 'retrieve'},
                                         name='evaluation_metric')),
]
