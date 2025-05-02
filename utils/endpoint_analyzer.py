import re
from urllib.parse import parse_qs, urlparse

class DynamicEndpointDetector:
    def __init__(self):
        self.patterns = {
            'uuid': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'numeric_id': r'\d+',
            'hash': r'[A-Fa-f0-9]{32,128}'
        }

    def normalize_endpoint(self, raw_url):
        """Convert dynamic endpoints to pattern-based signatures"""
        parsed = urlparse(raw_url)
        path = parsed.path
        
        # Replace dynamic segments with placeholders
        for param_type, regex in self.patterns.items():
            path = re.sub(regex, f'{{{param_type}}}', path, flags=re.IGNORECASE)
        
        return f"{parsed.netloc}{path}"

    def extract_parameters(self, raw_url):
        """Identify dynamic parameters in URL"""
        params = {}
        parsed = urlparse(raw_url)
        
        # Path parameters
        path_segments = parsed.path.split('/')
        for segment in path_segments:
            for param_type, regex in self.patterns.items():
                if re.fullmatch(regex, segment):
                    params[param_type] = params.get(param_type, 0) + 1
        
        # Query parameters
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            for value in values:
                for param_type, regex in self.patterns.items():
                    if re.fullmatch(regex, value):
                        params[f"query_{param_type}"] = params.get(f"query_{param_type}", 0) + 1
        
        return params