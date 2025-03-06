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
]