from django.urls import path

from .views import *

urlpatterns =[ 
    path('mitre_attack_active/',
         MITREAttackTacticViewSet.as_view({'get': 'list', 'post':'create'}, name='mitre_attack_active')),
    path('mitre_attack_active/<pk>/',
         MITREAttackTacticViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='mitre_attack_active')),
]