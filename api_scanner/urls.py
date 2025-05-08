from django.urls import path
from .views import *

urlpatterns = [
    path('mitre_attack/',
         MITREAttackTacticViewSet.as_view({'get': 'list'}, name='mitre_attack')),
    path('mitre_attack_technique/',
         MITREAttackTechniqueViewSet.as_view({'get': 'list'}, name='mitre_attack_technique')),
    
    path('api_test/',
         APITestViewSet.as_view({'get': 'list', 'post': 'create'}, name='api_test')),
    path('api_test/<slug>/',
         APITestViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='api_test')),
    
    path('security_test_case/',
         SecurityTestCaseViewSet.as_view({'get': 'list', 'post': 'create'}, name='security_test_case')),
    path('security_test_case/<slug>/',
         SecurityTestCaseViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='security_test_case')),
    
    
    path('api_test_execute/<api_test_slug>/',
         TestExecutionViewSet.as_view({'get': 'api_test_execute'},
                              name='api_test_execute')),
    
    path('test_execution/<slug>/',
         TestExecutionViewSet.as_view({'get': 'retrieve'},
                              name='test_execution')),
    
    path('test_executions_llm_analysis/<test_execution_slug>/',
         TestExecutionViewSet.as_view({'get': 'test_executions_llm_analysis'},
                              name='test_executions_llm_analysis')),
    
    path('test_executions_report/<test_execution_slug>/',
         TestExecutionViewSet.as_view({'get': 'test_executions_report'},
                              name='test_executions_report')),
    
    path('all_report/<test_execution_slug>/',
         TestExecutionViewSet.as_view({'get': 'get_report'},
                              name='get_report')),
    
    path('attack_simulation/',
         AttackSimulationViewSet.as_view({'get': 'list', 'post': 'create'}, name='attack_simulation')),
    path('attack_simulation/<slug>/',
         AttackSimulationViewSet.as_view({"get":"retrieve"},
                              name='attack_simulation')),
    
    path('report/<api_test_slug>/',
         ReportViewSet.as_view({"get":"test_execution_report"},
                              name='report')),
]

