# utils/ml_anomaly.py
import os
import logging
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, RepeatVector
from tensorflow.keras.optimizers import Adam
from django.conf import settings

# Configure logging
logger = logging.getLogger(__name__)

class MLModelError(Exception):
    """Custom exception for ML model errors"""
    pass

class MLAnomalyDetector:
    def __init__(self):
        """Initialize ML models with enhanced error handling"""
        try:
            # Configure TensorFlow logging
            os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress info messages
            logging.getLogger('tensorflow').setLevel(logging.WARNING)
            
            self.scaler = StandardScaler()
            self.models = {
                'isolation_forest': IsolationForest(
                    contamination=0.01,
                    random_state=42
                ),
                'lstm_autoencoder': self._build_lstm_autoencoder()
            }
            self.model_path = os.path.join(settings.BASE_DIR, 'ml_models')
            os.makedirs(self.model_path, exist_ok=True)
            
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Model initialization failed: {str(e)}")
            raise MLModelError(f"Model initialization failed: {str(e)}")

    def _build_lstm_autoencoder(self):
        """Build optimized LSTM Autoencoder for TF 2.19"""
        try:
            model = Sequential(name="lstm_anomaly_detector")
            # Encoder
            model.add(LSTM(128, activation='tanh', 
                         input_shape=(10, 1), 
                         return_sequences=False))
            model.add(RepeatVector(10))
            # Decoder
            model.add(LSTM(128, activation='tanh', 
                         return_sequences=True))
            model.add(Dense(1))
            
            model.compile(
                optimizer=Adam(learning_rate=0.001),
                loss='mae',  # Mean Absolute Error for better anomaly detection
                metrics=['mse']
            )
            return model
            
        except Exception as e:
            logger.error(f"LSTM construction failed: {str(e)}")
            raise MLModelError(f"Model architecture error: {str(e)}")

    # Rest of your methods remain the same...