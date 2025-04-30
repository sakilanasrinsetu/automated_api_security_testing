from django.urls import path
from api_scanner.views.scan_views import (
    APITestListCreateView,
    APITestDetailView,
    ExecuteAllTestCasesView,
)

urlpatterns = [
    path('tests/', APITestListCreateView.as_view(), name='api-tests-list-create'),
    path('tests/<slug:slug>/', APITestDetailView.as_view(), name='api-test-detail'),
    path('tests/<slug:slug>/execute/', ExecuteAllTestCasesView.as_view(), name='execute-api-test'),

]
