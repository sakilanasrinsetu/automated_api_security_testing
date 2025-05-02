from django.core.management.base import BaseCommand
from api_scanner.models import APILog
from utils.ml_anomaly import MLAnomalyDetector

class Command(BaseCommand):
    help = 'Train machine learning models for anomaly detection'

    def handle(self, *args, **options):
        self.stdout.write("Fetching training data...")
        historical_data = APILog.objects.all().values(
            'url', 'headers', 'body', 'response_time', 'status_code'
        )[:5000]  # Use last 5000 requests
        
        detector = MLAnomalyDetector()
        detector.train(historical_data)
        
        self.stdout.write(
            self.style.SUCCESS("Successfully trained and saved ML models!")
        )