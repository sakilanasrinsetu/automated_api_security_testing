from rest_framework import serializers
from .models import GroundTruthVulnerability, DetectionResult, EvaluationMetric


class GroundTruthVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = GroundTruthVulnerability
        fields = ['id', 'name', 'severity', 'cve_id', 'created_at']


class DetectionResultSerializer(serializers.ModelSerializer):
    vulnerability = GroundTruthVulnerabilitySerializer()

    class Meta:
        model = DetectionResult
        fields = ['id', 'scanner_name', 'vulnerability', 'detected', 'confidence_score', 'timestamp']


class EvaluationMetricSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvaluationMetric
        fields = ['id', 'scanner_name', 'precision', 'recall', 'f1_score', 'timestamp']
