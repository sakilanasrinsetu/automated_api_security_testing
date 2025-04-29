import uuid
import random
import string
import logging
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.exceptions import ValidationError
from api_scanner.models import (
    MITREAttackTactic, MITREAttackTechnique, APITest, SecurityTestCase,
    TestExecution, LLMAnalysis, Report, AttackSimulation, APILog, TestSchedule
)

logger = logging.getLogger(__name__)

def generate_mitre_slug():
    """Generate MITRE-compliant slug with a-z prefix and microsecond timestamp"""
    rand_char = random.choice(string.ascii_lowercase)
    timestamp = timezone.now().strftime("%Y%m%d%H%M%S%f")
    return f"{rand_char}-{timestamp}"

@receiver(pre_save)
def add_auto_slug(sender, instance, **kwargs):
    """Universal slug generator for all relevant models"""
    allowed_models = (MITREAttackTactic, MITREAttackTechnique, APITest, SecurityTestCase, TestExecution, LLMAnalysis, Report, AttackSimulation, APILog, TestSchedule)
    if sender not in allowed_models:
        return

    if hasattr(instance, 'slug') and not instance.slug:
        max_retries = 3
        for attempt in range(max_retries):
            slug = generate_mitre_slug()
            if not sender.objects.filter(slug=slug).exists():
                instance.slug = slug
                return
            logger.warning(f"Slug collision detected for {sender.__name__}, attempt {attempt + 1}")

        # Fallback if all retries fail
        instance.slug = f"{generate_mitre_slug()}-{uuid.uuid4().hex[:4]}"

@receiver(pre_save, sender=MITREAttackTechnique)
def validate_mitre_relationships(sender, instance, **kwargs):
    """Ensure each MITRE Technique is linked to a Tactic"""
    if not instance.tactic:
        raise ValidationError("MITRE techniques must be associated with a tactic.")

@receiver(pre_save, sender=SecurityTestCase)
def validate_severity(sender, instance, **kwargs):
    """Auto-correct severity for certain tactics"""
    technique = instance.mitre_attack_technique
    if 'Credential Access' in technique.tactic.name and instance.severity == 'Low':
        instance.severity = 'High'
