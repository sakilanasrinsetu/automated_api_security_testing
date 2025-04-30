from django.urls import path, include
from rest_framework.routers import DefaultRouter

from api_scanner.views.execution_views import ExecutionViewSet
from api_scanner.views.test_case_views import SecurityTestCaseViewSet
from .views.scan_views import APITestViewSet

router = DefaultRouter()

router.register(r'tests', APITestViewSet, basename='api-test')
router.register(r'test-cases', SecurityTestCaseViewSet, basename='test-case')
router.register(r'executions', ExecutionViewSet, basename='execution')


urlpatterns = [
    path('', include(router.urls)),
]