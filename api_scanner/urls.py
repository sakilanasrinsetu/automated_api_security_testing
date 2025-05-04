from django.urls import path
from .views import APITestCreateView

urlpatterns = [
    path('comprehensive_test/', APITestCreateView.as_view(), name='comprehensive-test')

]