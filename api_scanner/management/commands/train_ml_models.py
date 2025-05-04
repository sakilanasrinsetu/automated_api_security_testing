# api_scanner/management/commands/train_ml_models.py
from django.core.management.base import BaseCommand
from api_scanner.models import APILog
from utils.ml_anomaly import MLAnomalyDetector
from django.db.models import F

class Command(BaseCommand):
    help = 'Train machine learning models using enhanced API log data'

    def handle(self, *args, **options):
        self.stdout.write("🚀 Starting ML training with enhanced features...")
        
        # Get enriched training data
        historical_data = APILog.objects.annotate(
            api_url=F('api_test__endpoint'),
            http_method=F('api_test__http_method')
        ).values(
            # Newly added fields
            'actual_request_headers',
            'actual_request_body',
            'response_time_ms',
            
            # Existing core fields
            'api_url',
            'http_method',
            'response_code',
            'user_agent',
            'ip_address',
            
            # Temporal features
            'timestamp',
            
            # Status information
            'status',
            
            # Related test configuration
            'api_test__headers',  # Original test config headers
            'api_test__body'     # Original test config body
        )[:5000]

        self.stdout.write(f"📦 Loaded {len(historical_data)} records with new features")
        
        # Train model
        detector = MLAnomalyDetector()
        detector.train(historical_data)
        
        self.stdout.write(self.style.SUCCESS(
            f"✅ Training complete! Model now using: \n"
            f"- {len(historical_data)} samples\n"
            f"- {len(historical_data[0].keys())} features per sample\n"
            f"- New temporal/request features: response_time_ms, actual_request_*"
        ))