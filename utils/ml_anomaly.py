import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM
from django.conf import settings
import os

class MLAnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.models = {
            'isolation_forest': IsolationForest(contamination=0.01),
            'lstm_autoencoder': self._build_lstm_autoencoder()
        }
        self.model_path = os.path.join(settings.BASE_DIR, 'ml_models')
        self.load_models()

    def _build_lstm_autoencoder(self):
        model = Sequential([
            LSTM(64, activation='relu', input_shape=(10, 1),  # 10 time steps
            Dense(32, activation='relu'),
            Dense(64, activation='relu'),
            Dense(1, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def _extract_features(self, request_data):
        """Convert request metadata to numerical features"""
        return np.array([
            len(request_data['url']),          # URL length
            len(request_data['body']),         # Body size
            len(request_data['headers']),      # Header count
            request_data.get('response_time', 0),
            request_data.get('status_code', 0) // 100  # Status code class
        ]).reshape(1, -1)

    def train(self, historical_data):
        # Feature extraction
        features = np.array([self._extract_features(d) for d in historical_data])
        
        # Scale features
        self.scaler.fit(features)
        scaled_features = self.scaler.transform(features)
        
        # Train Isolation Forest
        self.models['isolation_forest'].fit(scaled_features)
        
        # Train LSTM (assuming time series data)
        if len(historical_data) >= 100:
            time_series = self._create_sequences(scaled_features)
            self.models['lstm_autoencoder'].fit(
                time_series, time_series,
                epochs=10,
                batch_size=32,
                shuffle=True
            )
        
        # Save models
        self.save_models()

    def predict(self, request_data):
        features = self.scaler.transform(self._extract_features(request_data))
        
        # Isolation Forest prediction
        if_score = self.models['isolation_forest'].score_samples([features])[0]
        
        # LSTM reconstruction error
        sequence = self._create_sequences(features.reshape(1, -1))
        lstm_error = self.models['lstm_autoencoder'].evaluate(
            sequence, sequence, verbose=0
        )
        
        return {
            'isolation_forest_score': if_score,
            'lstm_reconstruction_error': lstm_error,
            'combined_risk': (if_score * 0.7) + (lstm_error * 0.3)
        }

    def _create_sequences(self, data, window_size=10):
        """Convert data to time series sequences"""
        sequences = []
        for i in range(len(data) - window_size):
            sequences.append(data[i:i+window_size])
        return np.array(sequences)

    def save_models(self):
        os.makedirs(self.model_path, exist_ok=True)
        joblib.dump(self.models['isolation_forest'], 
                   os.path.join(self.model_path, 'isolation_forest.joblib'))
        self.models['lstm_autoencoder'].save(
            os.path.join(self.model_path, 'lstm_autoencoder.keras'))

    def load_models(self):
        if os.path.exists(os.path.join(self.model_path, 'isolation_forest.joblib')):
            self.models['isolation_forest'] = joblib.load(
                os.path.join(self.model_path, 'isolation_forest.joblib'))
        
        if os.path.exists(os.path.join(self.model_path, 'lstm_autoencoder.keras')):
            self.models['lstm_autoencoder'] = load_model(
                os.path.join(self.model_path, 'lstm_autoencoder.keras'))