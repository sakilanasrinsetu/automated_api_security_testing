from rest_framework import serializers
from .models import *


class GroundTruthVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = GroundTruthVulnerability
        fields = [
            'id', 
            'name', 
            'severity',
            'cve_id',
            'created_at'
            ]

class DetectionResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionResult
        fields = [
            'id', 
            'vulnerability', 
            'detected',
            'confidence_score',
            'scanner_name',
            'timestamp'
            ]
        
        
class EvaluationMetricSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvaluationMetric
        fields = [
            'id', 
            'scanner_name', 
            'precision',
            'recall',
            'f1_score',
            'timestamp'
            ]