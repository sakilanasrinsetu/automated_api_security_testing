from django.urls import path

from api_security.views import *

urlpatterns =[ 
    path('mitre_attack_active/',
         MITREAttackTacticViewSet.as_view({'get': 'list', 'post':'create'}, name='mitre_attack_active')),
    
    path('mitre_attack_active/<slug>/',
         MITREAttackTacticViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='mitre_attack_active')),
    path('mitre_attack_technique/',
         MITREAttackTechniqueViewSet.as_view({'get': 'list', 'post':'create'}, name='mitre_attack_technique')),
    
    path('mitre_attack_technique/<slug>/',
         MITREAttackTechniqueViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='mitre_attack_technique')),
    path('api_test/',
         APITestViewSet.as_view({'get': 'list', 'post':'create'}, name='api_test')),
    
    path('api_test/<slug>/',
         APITestViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='api_test')),
    path('security_test_case/',
         SecurityTestCaseViewSet.as_view({'get': 'list', 'post':'create'}, name='security_test_case')),
    
    path('security_test_case/<slug>/',
         SecurityTestCaseViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='security_test_case')),
]