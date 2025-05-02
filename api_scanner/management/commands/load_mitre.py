# api_scanner/management/commands/load_mitre.py
import json
import requests
from django.core.management.base import BaseCommand
from django.db import transaction
from api_scanner.models import MITREAttackTactic, MITREAttackTechnique

class Command(BaseCommand):
    help = 'Load MITRE ATT&CK data from official sources'

    def handle(self, *args, **kwargs):
        self.stdout.write("🚀 Starting MITRE ATT&CK import...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            with transaction.atomic():
                self._delete_existing_data()
                data = requests.get(url).json()
                self._process_data(data['objects'])
                self.stdout.write(self.style.SUCCESS("✅ MITRE data loaded successfully!"))
        except Exception as e:
            self.stderr.write(f"❌ Import failed: {str(e)}")
            raise

    def _delete_existing_data(self):
        MITREAttackTechnique.objects.all().delete()
        MITREAttackTactic.objects.all().delete()
        self.stdout.write("🧹 Cleared existing MITRE data")

    def _process_data(self, objects):
        tactic_map = self._create_tactics(objects)
        self._create_techniques(objects, tactic_map)

    def _create_tactics(self, objects):
        tactics = {}
        for obj in objects:
            if obj['type'] == 'x-mitre-tactic':
                ext_ref = next((r for r in obj['external_references'] if r['source_name'] == 'mitre-attack'), None)
                if ext_ref:
                    tactic, _ = MITREAttackTactic.objects.update_or_create(
                        mitre_attack_id=ext_ref['external_id'],
                        defaults={
                            'name': obj['name'],
                            'description': obj.get('description', ''),
                            'slug': obj['x_mitre_shortname']
                        }
                    )
                    tactics[obj['x_mitre_shortname']] = tactic
                    self.stdout.write(f"🛡️ Created tactic: {tactic.name} ({tactic.mitre_attack_id})")
        return tactics

    def _create_techniques(self, objects, tactic_map):
        technique_count = 0
        for obj in objects:
            if obj['type'] == 'attack-pattern':
                try:
                    ext_ref = next(r for r in obj['external_references'] if r['source_name'] == 'mitre-attack')
                    phase = next(p for p in obj['kill_chain_phases'] if p['kill_chain_name'] == 'mitre-attack')
                    
                    technique_id = ext_ref['external_id']
                    tactic = tactic_map[phase['phase_name']]
                    
                    MITREAttackTechnique.objects.update_or_create(
                        mitre_attack_technique_id=technique_id,
                        defaults={
                            'name': obj['name'],
                            'description': obj.get('description', ''),
                            'tactic': tactic,
                            'slug': technique_id.lower().replace('.', '-'),
                            'severity_weight': 4.0 if '.001' in technique_id else 3.0
                        }
                    )
                    technique_count += 1
                    self.stdout.write(f"🔍 Created technique: {technique_id}")
                except (StopIteration, KeyError) as e:
                    self.stderr.write(f"⚠️ Skipping technique: {str(e)}")
        
        self.stdout.write(f"📊 Total techniques imported: {technique_count}")

# Run with:
# python manage.py load_mitre