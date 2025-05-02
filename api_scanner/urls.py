from django.urls import path, include 

from .views import *

urlpatterns =[
     path('api_test/',
         APITestViewSet.as_view({'get': 'list', 'post': 'create'}, name='api_test')),
     path('api_test/<slug>/',
         APITestViewSet.as_view({'delete': 'destroy',
                              "patch":"update", "get":"retrieve"},
                              name='api_test')),
]