from django.db import models


class GroundTruthVulnerability(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    cve_id = models.CharField(max_length=50, blank=True, null=True, help_text="Optional CVE ID if exists")
    severity = models.CharField(max_length=50, choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Ground Truth Vulnerability"
        verbose_name_plural = "Ground Truth Vulnerabilities"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.severity})"


class DetectionResult(models.Model):
    """
    Stores the detection results of your automated scanner.
    Later compared against GroundTruthVulnerability.
    """
    vulnerability = models.ForeignKey(GroundTruthVulnerability, on_delete=models.CASCADE)
    detected = models.BooleanField(default=False)
    confidence_score = models.FloatField(default=0.0, help_text="Confidence score between 0.0 and 1.0")
    scanner_name = models.CharField(max_length=255, help_text="Which scanner/tool produced this result?")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Detection Result"
        verbose_name_plural = "Detection Results"
        ordering = ['-timestamp']

    def __str__(self):
        status = "Detected" if self.detected else "Missed"
        return f"{self.scanner_name}: {self.vulnerability.name} - {status}"


class EvaluationMetric(models.Model):
    """
    Stores evaluation metrics calculated from detections, such as precision, recall, etc.
    """
    scanner_name = models.CharField(max_length=255)
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Evaluation Metric"
        verbose_name_plural = "Evaluation Metrics"
        ordering = ['-timestamp']

    def __str__(self):
        return f"Metrics for {self.scanner_name} - F1: {self.f1_score:.2f}"
