from celery import shared_task
from django.core.management import call_command

@shared_task
def retrain_models():
    call_command('train_models')