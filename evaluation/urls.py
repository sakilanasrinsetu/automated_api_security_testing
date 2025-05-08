from django.urls import path
from evaluation.views import *

urlpatterns = [
    
    path('ground_truth_vulnerability/', 
         GroundTruthVulnerabilityViewSet.as_view({'get': 'list'}, name='ground_truth_vulnerability')),
#     path('ground_truth_vulnerability/<pk>/',
#          GroundTruthVulnerabilityViewSet.as_view({'delete': 'destroy', 'patch': 'update', 'get': 'retrieve'},
#                                                  name='ground_truth_vulnerability')),
    
    # EvaluationMetric endpoints
    # path('evaluation_metric/', 
    #      EvaluationMetricViewSet.as_view({'get': 'list', 'post': 'create'}, name='evaluation_metric')),
    # path('evaluation_metric/<pk>/', 
    #      EvaluationMetricViewSet.as_view({'delete': 'destroy', 'patch': 'update', 'get': 'retrieve'},
    #                                      name='evaluation_metric')),
]
