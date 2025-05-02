import statistics
from collections import defaultdict

from utils.endpoint_analyzer import DynamicEndpointDetector

class APIBehaviorProfiler:
    def __init__(self):
        self.endpoint_profiles = defaultdict(lambda: {
            'request_counts': 0,
            'param_distributions': defaultdict(list),
            'response_sizes': [],
            'response_times': []
        })

    def analyze_request(self, request):
        normalized_endpoint = DynamicEndpointDetector().normalize_endpoint(request.url)
        params = DynamicEndpointDetector().extract_parameters(request.url)
        
        profile = self.endpoint_profiles[normalized_endpoint]
        profile['request_counts'] += 1
        
        # Track parameter patterns
        for param_type, count in params.items():
            profile['param_distributions'][param_type].append(count)
        
        # Track response characteristics
        profile['response_sizes'].append(request.response_size)
        profile['response_times'].append(request.response_time)
        
        return self._detect_anomalies(normalized_endpoint, profile)

    def _detect_anomalies(self, endpoint, profile):
        anomalies = []
        
        # Parameter count anomalies
        for param_type, counts in profile['param_distributions'].items():
            if len(counts) > 10:  # Only check after sufficient data
                mean = statistics.mean(counts)
                std_dev = statistics.stdev(counts)
                current = counts[-1]
                if abs(current - mean) > 3 * std_dev:
                    anomalies.append(f"Parameter {param_type} count anomaly")

        # Response size anomalies
        if len(profile['response_sizes']) > 10:
            q75, q25 = np.percentile(profile['response_sizes'], [75, 25])
            iqr = q75 - q25
            current = profile['response_sizes'][-1]
            if current > q75 + 1.5*iqr or current < q25 - 1.5*iqr:
                anomalies.append("Response size anomaly")

        return {
            'endpoint': endpoint,
            'anomalies': anomalies,
            'risk_score': len(anomalies) * 20  # 0-100 scale
        }