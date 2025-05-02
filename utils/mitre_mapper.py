MITRE_TECHNIQUE_MAP = {
    'parameter_anomaly': {
        'techniques': ['T1190', 'T1211'],
        'tactics': ['TA0001', 'TA0040'],
        'confidence': 0.75
    },
    'unusual_response_size': {
        'techniques': ['T1499', 'T1530'],
        'tactics': ['TA0040', 'TA0043'],
        'confidence': 0.65
    },
    'high_frequency_requests': {
        'techniques': ['T1498', 'T1499'],
        'tactics': ['TA0040'],
        'confidence': 0.85
    },
    'credential_patterns': {
        'techniques': ['T1110', 'T1552.001'],
        'tactics': ['TA0006'],
        'confidence': 0.9
    }
}

class MitreTechniqueMapper:
    def map_anomalies(self, anomalies):
        detected_techniques = []
        
        for anomaly in anomalies:
            if 'credential' in anomaly.lower():
                entry = MITRE_TECHNIQUE_MAP['credential_patterns']
                detected_techniques.append({
                    'technique': entry['techniques'],
                    'tactics': entry['tactics'],
                    'confidence': entry['confidence'],
                    'evidence': anomaly
                })
            elif 'parameter' in anomaly.lower():
                entry = MITRE_TECHNIQUE_MAP['parameter_anomaly']
                detected_techniques.append({
                    'technique': entry['techniques'],
                    'tactics': entry['tactics'],
                    'confidence': entry['confidence'],
                    'evidence': anomaly
                })
            # Add more mappings as needed
        
        return self._prioritize_findings(detected_techniques)

    def _prioritize_findings(self, findings):
        return sorted(
            findings,
            key=lambda x: x['confidence'],
            reverse=True
        )[:5]  # Return top 5 findings