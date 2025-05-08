from django.contrib import admin
from .models import GroundTruthVulnerability, DetectionResult, EvaluationMetric


@admin.register(GroundTruthVulnerability)
class GroundTruthVulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('name','id', 'severity', 'cve_id', 'created_at')
    search_fields = ('name', 'cve_id', 'description')
    list_filter = ('severity', 'created_at')
    readonly_fields = ('created_at',)


@admin.register(DetectionResult)
class DetectionResultAdmin(admin.ModelAdmin):
    list_display = ('scanner_name', 'vulnerability', 'detected', 'confidence_score', 'timestamp')
    search_fields = ('scanner_name', 'vulnerability__name')
    list_filter = ('detected', 'scanner_name', 'timestamp')
    readonly_fields = ('timestamp',)


@admin.register(EvaluationMetric)
class EvaluationMetricAdmin(admin.ModelAdmin):
    list_display = ('scanner_name', 'precision', 'recall', 'f1_score', 'timestamp')
    search_fields = ('scanner_name',)
    list_filter = ('scanner_name', 'timestamp')
    readonly_fields = ('timestamp',)
