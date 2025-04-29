from utils.custom_veinlet import CustomViewSet
from .models import GroundTruthVulnerability, DetectionResult, EvaluationMetric
from .serializers import GroundTruthVulnerabilitySerializer, DetectionResultSerializer, EvaluationMetricSerializer


class GroundTruthVulnerabilityViewSet(CustomViewSet):
    """
    ViewSet for managing GroundTruthVulnerability objects
    """
    queryset = GroundTruthVulnerability.objects.all()
    serializer_class = GroundTruthVulnerabilitySerializer
    lookup_field = "pk"  # Look up by pk # Filter by scanner_name


class DetectionResultViewSet(CustomViewSet):
    """
    ViewSet for managing DetectionResult objects
    """
    queryset = DetectionResult.objects.all()
    serializer_class = DetectionResultSerializer
    lookup_field = "pk"  # Look up by pk


class EvaluationMetricViewSet(CustomViewSet):
    """
    ViewSet for managing EvaluationMetric objects
    """
    queryset = EvaluationMetric.objects.all()
    serializer_class = EvaluationMetricSerializer
    lookup_field = "pk"  # Look up by pk
