import json
import logging
from django.core.exceptions import ObjectDoesNotExist
from django.core.cache import cache
from api_scanner.models import MITREAttackTechnique, MITREAttackTactic

logger = logging.getLogger(__name__)
MITRE_CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours

def detect_mitre_patterns(api_test):
    """Analyze API configuration for MITRE ATT&CK patterns"""
    detected = []
    logger.debug(f"Starting MITRE analysis for API Test {api_test.id}")
    
    try:
        # Credential Exposure
        if _check_credential_exposure(api_test):
            detected.extend(_get_techniques_by_ids(["T1552.001"]))
        
        # Authentication Weakness
        if _check_auth_weakness(api_test):
            detected.append(_get_technique("T1078"))
        
        # IDOR Detection
        if _check_idor(api_test):
            detected.append(_get_technique("T1531"))
            
        # Data Exposure
        if _check_data_exposure(api_test):
            detected.append(_get_technique("T1432"))
            
        # Rate Limiting
        if _check_rate_limiting(api_test):
            detected.append(_get_technique("T1498"))

    except Exception as e:
        logger.error(f"Detection failed: {str(e)}", exc_info=True)
    
    return list(filter(None, set(detected)))

def calculate_vulnerability_score(detected_techniques):
    """Calculate risk score 0-100 based on detected techniques"""
    if not detected_techniques:
        return 0.0
    
    try:
        total = sum(t.severity_weight for t in detected_techniques)
        return f"{round(min((total / len(detected_techniques)) * 25, 100.0), 3)}%"
    except AttributeError:
        logger.error("Missing severity_weight in MITRE techniques")
        return 0.0

def serialize_mitre_data(detected_techniques):
    """Serialize MITRE data for API response"""
    return {
        "tactics": [_serialize_tactic(t.tactic) for t in detected_techniques if t],
        "techniques": [_serialize_technique(t) for t in detected_techniques if t],
        "severity_breakdown": _get_severity_distribution(detected_techniques)
    }

# Helper functions ------------------------------------------------------------

def _get_technique(technique_id):
    """Get single technique with caching"""
    cache_key = f"mitre_tech_{technique_id}"
    if (tech := cache.get(cache_key)) is None:
        try:
            tech = MITREAttackTechnique.objects.get(
                mitre_attack_technique_id=technique_id
            )
            cache.set(cache_key, tech, MITRE_CACHE_TIMEOUT)
        except ObjectDoesNotExist:
            logger.warning(f"MITRE Technique {technique_id} not found")
            return None
    return tech

def _get_techniques_by_ids(technique_ids):
    """Get multiple techniques"""
    return [t for t in (_get_technique(tid) for tid in technique_ids) if t]

def _check_credential_exposure(api_test):
    """Detect credentials in insecure locations"""
    try:
        body = json.loads(api_test.body) if isinstance(api_test.body, str) else api_test.body
    except json.JSONDecodeError:
        return False

    sensitive = {'password', 'secret', 'token', 'credential'}
    fields = [k.lower() for k in body.keys()]
    
    return (
        api_test.http_method == 'GET' and 
        any(f in fields for f in sensitive)
    ) or (
        api_test.auth_type == 'None' and 
        any(f in fields for f in sensitive)
    )

def _check_auth_weakness(api_test):
    """Check authentication vulnerabilities"""
    endpoint = api_test.endpoint.lower()
    auth = api_test.auth_type
    creds = api_test.auth_credentials or {}
    
    return (
        auth == 'None' and any(kw in endpoint for kw in {'login', 'auth'})
    ) or (
        auth == 'Basic' and not creds.get('encrypted')
    ) or (
        auth == 'JWT' and not creds.get('signing_key')
    )

def _check_idor(api_test):
    """Insecure Direct Object Reference check"""
    body = api_test.body or {}
    return any(
        param in body for param in {'id', 'user_id', 'account_id'}
    ) and 'authorization' not in (api_test.headers or {}).lower()

def _check_data_exposure(api_test):
    """Excessive data exposure check"""
    response = api_test.expected_response or {}
    return any(field in response for field in {'password', 'token'})

def _check_rate_limiting(api_test):
    """Check for rate limiting headers"""
    headers = api_test.headers or {}
    return not any(
        header_key in {'ratelimit-limit', 'x-ratelimit-limit'}
        for header_key in map(str.lower, headers.keys())
    )

def _serialize_tactic(tactic):
    return {
        "id": tactic.mitre_attack_id,
        "name": tactic.name,
        "mitre_url": f"https://attack.mitre.org/tactics/{tactic.mitre_attack_id}"
    }

def _serialize_technique(technique):
    return {
        "id": technique.mitre_attack_technique_id,
        "name": technique.name,
        "severity": _get_technique_severity(technique),
        "mitre_url": f"https://attack.mitre.org/techniques/{technique.mitre_attack_technique_id}",
        "recommendations": _get_recommendations(technique)
    }

def _get_technique_severity(technique):
    severity_map = {
        'T1552.001': 'Critical',
        'T1078': 'High',
        'T1531': 'Medium',
        'T1432': 'High',
        'T1498': 'Medium'
    }
    return severity_map.get(technique.mitre_attack_technique_id, 'Medium')

def _get_recommendations(technique):
    return {
        "T1552.001": [
            "Never send credentials via GET requests",
            "Use HTTPS and encrypt sensitive data"
        ],
        "T1078": [
            "Implement multi-factor authentication",
            "Monitor failed login attempts"
        ],
        "T1531": [
            "Implement access controls",
            "Use UUIDs instead of sequential IDs"
        ],
        "T1432": [
            "Implement data minimization",
            "Encrypt sensitive data at rest"
        ],
        "T1498": [
            "Implement rate limiting",
            "Use CAPTCHA for repeated attempts"
        ]
    }.get(technique.mitre_attack_technique_id, ["Review OWASP API Security guidelines"])

def _get_severity_distribution(techniques):
    dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for t in techniques:
        dist[_get_technique_severity(t)] += 1
    return dist