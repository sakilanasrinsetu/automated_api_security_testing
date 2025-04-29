from django.core.management.base import BaseCommand
from evaluation.models import GroundTruthVulnerability, DetectionResult, EvaluationMetric
from django.db.models import Count


class Command(BaseCommand):
    help = "Calculate evaluation metrics (Precision, Recall, F1-score) for scanners."

    def handle(self, *args, **kwargs):
        scanners = DetectionResult.objects.values_list('scanner_name', flat=True).distinct()

        for scanner in scanners:
            results = DetectionResult.objects.filter(scanner_name=scanner)

            true_positives = results.filter(detected=True).count()
            false_positives = results.filter(detected=True).exclude(vulnerability__in=GroundTruthVulnerability.objects.all()).count()
            false_negatives = GroundTruthVulnerability.objects.exclude(id__in=results.filter(detected=True).values_list('vulnerability_id', flat=True)).count()

            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            EvaluationMetric.objects.create(
                scanner_name=scanner,
                precision=precision,
                recall=recall,
                f1_score=f1_score
            )

            self.stdout.write(self.style.SUCCESS(
                f"Metrics calculated for {scanner} - Precision: {precision:.2f}, Recall: {recall:.2f}, F1 Score: {f1_score:.2f}"
            ))
