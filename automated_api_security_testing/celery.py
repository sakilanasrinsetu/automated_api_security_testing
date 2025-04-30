import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'automated_api_security_testing.settings')

app = Celery('automated_api_security_testing')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()