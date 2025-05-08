from django.core.management.base import BaseCommand
from evaluation.models import GroundTruthVulnerability

class Command(BaseCommand):
    help = 'Bulk add Ground Truth Vulnerabilities'

    def handle(self, *args, **kwargs):
        # Sample data to add to GroundTruthVulnerability model
        vulnerabilities_data = [
            {
                "name": "SQL Injection",
                "description": "SQL Injection vulnerability in the API.",
                "cve_id": "CVE-2021-1234",
                "severity": "High"
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "description": "XSS vulnerability in API where user input is not sanitized.",
                "cve_id": "CVE-2020-5678",
                "severity": "Medium"
            },
            {
                "name": "Broken Authentication",
                "description": "Vulnerability in the authentication system of the API.",
                "cve_id": "CVE-2021-9103",
                "severity": "Critical"
            },
            {
                "name": "Sensitive Data Exposure",
                "description": "Sensitive data is exposed over an insecure connection.",
                "cve_id": "CVE-2021-3449",
                "severity": "High"
            },
            {
                "name": "Cross-Site Request Forgery (CSRF)",
                "description": "CSRF vulnerability where user actions are performed without their consent.",
                "cve_id": "CVE-2020-1020",
                "severity": "Medium"
            },
            {
                "name": "Command Injection",
                "description": "Command injection vulnerability where an attacker can execute arbitrary commands.",
                "cve_id": "CVE-2021-2213",
                "severity": "High"
            },
            {
                "name": "Path Traversal",
                "description": "An attacker can read files outside the intended directory by manipulating file paths.",
                "cve_id": "CVE-2020-2698",
                "severity": "Medium"
            },
            {
                "name": "Privilege Escalation",
                "description": "An attacker can gain unauthorized access to higher privileges in the system.",
                "cve_id": "CVE-2021-2865",
                "severity": "Critical"
            },
            {
                "name": "Remote Code Execution (RCE)",
                "description": "Remote Code Execution vulnerability where an attacker can run arbitrary code remotely.",
                "cve_id": "CVE-2020-0601",
                "severity": "Critical"
            },
            {
                "name": "Denial of Service (DoS)",
                "description": "DoS vulnerability that causes the system to crash or become unavailable.",
                "cve_id": "CVE-2021-27853",
                "severity": "High"
            },
            {
                "name": "Buffer Overflow",
                "description": "Buffer overflow vulnerability where data can overflow the buffer causing unexpected behavior.",
                "cve_id": "CVE-2021-2002",
                "severity": "Critical"
            },
            {
                "name": "Unvalidated Redirects and Forwards",
                "description": "Vulnerability that allows an attacker to redirect users to malicious websites.",
                "cve_id": "CVE-2020-1108",
                "severity": "Medium"
            },
            {
                "name": "Man-in-the-Middle (MitM) Attack",
                "description": "Vulnerability where an attacker can intercept and alter communications between two parties.",
                "cve_id": "CVE-2021-33558",
                "severity": "High"
            },
            {
                "name": "File Inclusion Vulnerability",
                "description": "Local/Remote file inclusion vulnerability that allows an attacker to include files on the server.",
                "cve_id": "CVE-2020-15947",
                "severity": "High"
            },
            {
                "name": "XML External Entity (XXE) Injection",
                "description": "Vulnerability where an attacker can inject malicious XML code to gain access to internal resources.",
                "cve_id": "CVE-2020-15113",
                "severity": "High"
            },
            {
                "name": "Directory Listing",
                "description": "Directory listing vulnerability where unauthorized users can view sensitive files in a web server directory.",
                "cve_id": "CVE-2021-2877",
                "severity": "Medium"
            },
            {
                "name": "Clickjacking",
                "description": "Clickjacking vulnerability where malicious content can trick users into clicking on something unintended.",
                "cve_id": "CVE-2020-1952",
                "severity": "Low"
            },
            {
                "name": "Weak Password Policy",
                "description": "Weak password policy vulnerability where the system allows easily guessable passwords.",
                "cve_id": "CVE-2021-2271",
                "severity": "Medium"
            },
            {
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "Vulnerability where the server makes requests to internal or external resources on behalf of the attacker.",
                "cve_id": "CVE-2020-5283",
                "severity": "High"
            },
            {
                "name": "Improper Input Validation",
                "description": "Failure to validate input leading to security vulnerabilities such as buffer overflow or injection attacks.",
                "cve_id": "CVE-2020-6235",
                "severity": "Medium"
            },
            # Additional vulnerabilities
            {
                "name": "Denial of Service via Resource Exhaustion",
                "description": "A DoS vulnerability where attackers cause resource exhaustion leading to system unavailability.",
                "cve_id": "CVE-2021-1236",
                "severity": "Medium"
            },
            {
                "name": "Unencrypted Data Transmission",
                "description": "Sensitive data is transmitted without encryption, making it susceptible to interception.",
                "cve_id": "CVE-2022-4567",
                "severity": "High"
            },
            {
                "name": "Insufficient Logging and Monitoring",
                "description": "Lack of proper logging and monitoring can allow attackers to operate undetected.",
                "cve_id": "CVE-2021-3158",
                "severity": "Medium"
            },
            {
                "name": "Directory Traversal Attack",
                "description": "An attacker is able to traverse the file system directories, potentially exposing sensitive files.",
                "cve_id": "CVE-2021-6789",
                "severity": "High"
            },
            {
                "name": "Privilege Escalation due to Insufficient Access Control",
                "description": "An attacker can escalate their privileges due to lack of proper access controls.",
                "cve_id": "CVE-2021-1357",
                "severity": "Critical"
            },
            {
                "name": "Broken Access Control",
                "description": "Vulnerabilities where attackers can bypass user access control restrictions.",
                "cve_id": "CVE-2021-5300",
                "severity": "Critical"
            },
            {
                "name": "Session Fixation",
                "description": "Vulnerability where an attacker can fix the user's session ID and hijack their session.",
                "cve_id": "CVE-2021-1052",
                "severity": "Medium"
            },
            {
                "name": "API Rate Limiting Bypass",
                "description": "Vulnerabilities that allow attackers to bypass API rate limiting mechanisms.",
                "cve_id": "CVE-2022-0115",
                "severity": "High"
            },
            {
                "name": "Cross-Site WebSocket Hijacking",
                "description": "Vulnerability where attackers can hijack WebSocket connections and inject malicious commands.",
                "cve_id": "CVE-2022-0143",
                "severity": "Critical"
            },
            {
                "name": "Insecure API Endpoints",
                "description": "API endpoints that are not properly secured, allowing unauthorized access.",
                "cve_id": "CVE-2021-1237",
                "severity": "High"
            },
            {
                "name": "Improper Certificate Validation",
                "description": "Vulnerability where the system does not properly validate SSL/TLS certificates.",
                "cve_id": "CVE-2021-1238",
                "severity": "Critical"
            },
            {
                "name": "Insecure Direct Object Reference (IDOR)",
                "description": "Vulnerability where an attacker can access objects directly without proper authorization.",
                "cve_id": "CVE-2021-1239",
                "severity": "High"
            },
            {
                "name": "Open Redirect",
                "description": "Vulnerability where an attacker can redirect users to malicious sites.",
                "cve_id": "CVE-2021-1240",
                "severity": "Medium"
            },
            {
                "name": "Insufficient Security Headers",
                "description": "Lack of security headers in HTTP responses, making the application vulnerable to attacks.",
                "cve_id": "CVE-2021-1241",
                "severity": "Low"
            },
            {
                "name": "XML Injection",
                "description": "Vulnerability where an attacker can inject malicious XML code into the system.",
                "cve_id": "CVE-2021-1242",
                "severity": "High"
            },
            {
                "name": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
                "description": "Vulnerability where CORS policies are not properly configured, allowing unauthorized access.",
                "cve_id": "CVE-2021-1243",
                "severity": "Medium"
            },
            {
                "name": "Improper Error Handling",
                "description": "Vulnerability where error messages reveal sensitive information to attackers.",
                "cve_id": "CVE-2021-1244",
                "severity": "Low"
            },
            {
                "name": "Insecure API Key Storage",
                "description": "API keys are stored insecurely, making them vulnerable to theft.",
                "cve_id": "CVE-2021-1245",
                "severity": "High"
            },
            {
                "name": "Exposed Administration Interface",
                "description": "Administration interface is exposed to the public without proper authentication.",
                "cve_id": "CVE-2021-1246",
                "severity": "Critical"
            },
            {
                "name": "Weak Encryption Algorithms",
                "description": "Use of weak encryption algorithms that can be easily broken by attackers.",
                "cve_id": "CVE-2021-1247",
                "severity": "High"
            },
            {
                "name": "Insecure File Upload",
                "description": "Vulnerability where an attacker can upload malicious files to the server.",
                "cve_id": "CVE-2021-1248",
                "severity": "Critical"
            },
            {
                "name": "Improper Session Management",
                "description": "Vulnerability where session tokens are not properly managed, allowing session hijacking.",
                "cve_id": "CVE-2021-1249",
                "severity": "High"
            },
            {
                "name": "Unrestricted File Upload",
                "description": "Vulnerability where an attacker can upload any file type to the server.",
                "cve_id": "CVE-2021-1250",
                "severity": "Critical"
            },
            {
                "name": "Insecure API Authentication",
                "description": "API authentication mechanisms that are weak or easily bypassed.",
                "cve_id": "CVE-2021-1251",
                "severity": "High"
            },
            {
                "name": "Improper Access Control",
                "description": "Vulnerability where access control mechanisms are not properly implemented.",
                "cve_id": "CVE-2021-1252",
                "severity": "Critical"
            },
            {
                "name": "Insecure API Rate Limiting",
                "description": "API rate limiting mechanisms that can be easily bypassed by attackers.",
                "cve_id": "CVE-2021-1253",
                "severity": "High"
            },
            {
                "name": "Insecure API Versioning",
                "description": "API versioning mechanisms that expose sensitive information or functionality.",
                "cve_id": "CVE-2021-1254",
                "severity": "Medium"
            },
            {
                "name": "Insecure API Caching",
                "description": "API caching mechanisms that expose sensitive data to unauthorized users.",
                "cve_id": "CVE-2021-1255",
                "severity": "High"
            },
            {
                "name": "Insecure API Documentation",
                "description": "API documentation that exposes sensitive information or functionality.",
                "cve_id": "CVE-2021-1256",
                "severity": "Medium"
            },
            {
                "name": "Insecure API Gateway Configuration",
                "description": "API gateway configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1257",
                "severity": "High"
            },
            {
                "name": "Insecure API Proxy Configuration",
                "description": "API proxy configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1258",
                "severity": "High"
            },
            {
                "name": "Insecure API Firewall Configuration",
                "description": "API firewall configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1259",
                "severity": "High"
            },
            {
                "name": "Insecure API Load Balancer Configuration",
                "description": "API load balancer configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1260",
                "severity": "High"
            },
            {
                "name": "Insecure API CDN Configuration",
                "description": "API CDN configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1261",
                "severity": "High"
            },
            {
                "name": "Insecure API DNS Configuration",
                "description": "API DNS configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1262",
                "severity": "High"
            },
            {
                "name": "Insecure API Network Configuration",
                "description": "API network configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1263",
                "severity": "High"
            },
            {
                "name": "Insecure API Database Configuration",
                "description": "API database configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1264",
                "severity": "High"
            },
            {
                "name": "Insecure API Storage Configuration",
                "description": "API storage configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1265",
                "severity": "High"
            },
            {
                "name": "Insecure API Backup Configuration",
                "description": "API backup configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1266",
                "severity": "High"
            },
            {
                "name": "Insecure API Monitoring Configuration",
                "description": "API monitoring configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1267",
                "severity": "High"
            },
            {
                "name": "Insecure API Logging Configuration",
                "description": "API logging configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1268",
                "severity": "High"
            },
            {
                "name": "Insecure API Alerting Configuration",
                "description": "API alerting configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1269",
                "severity": "High"
            },
            {
                "name": "Insecure API Incident Response Configuration",
                "description": "API incident response configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1270",
                "severity": "High"
            },
            {
                "name": "Insecure API Disaster Recovery Configuration",
                "description": "API disaster recovery configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1271",
                "severity": "High"
            },
            {
                "name": "Insecure API Business Continuity Configuration",
                "description": "API business continuity configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1272",
                "severity": "High"
            },
            {
                "name": "Insecure API Compliance Configuration",
                "description": "API compliance configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1273",
                "severity": "High"
            },
            {
                "name": "Insecure API Governance Configuration",
                "description": "API governance configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1274",
                "severity": "High"
            },
            {
                "name": "Insecure API Risk Management Configuration",
                "description": "API risk management configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1275",
                "severity": "High"
            },
            {
                "name": "Insecure API Threat Intelligence Configuration",
                "description": "API threat intelligence configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1276",
                "severity": "High"
            },
            {
                "name": "Insecure API Vulnerability Management Configuration",
                "description": "API vulnerability management configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1277",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Awareness Training Configuration",
                "description": "API security awareness training configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1278",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Policy Configuration",
                "description": "API security policy configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1279",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Standards Configuration",
                "description": "API security standards configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1280",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Framework Configuration",
                "description": "API security framework configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1281",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Architecture Configuration",
                "description": "API security architecture configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1282",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Design Configuration",
                "description": "API security design configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1283",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Engineering Configuration",
                "description": "API security engineering configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1284",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Operations Configuration",
                "description": "API security operations configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1285",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Testing Configuration",
                "description": "API security testing configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1286",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Assessment Configuration",
                "description": "API security assessment configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1287",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Audit Configuration",
                "description": "API security audit configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1288",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Review Configuration",
                "description": "API security review configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1289",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Assessment Configuration",
                "description": "API security assessment configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1290",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Testing Configuration",
                "description": "API security testing configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1291",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Operations Configuration",
                "description": "API security operations configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1292",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Engineering Configuration",
                "description": "API security engineering configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1293",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Design Configuration",
                "description": "API security design configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1294",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Architecture Configuration",
                "description": "API security architecture configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1295",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Framework Configuration",
                "description": "API security framework configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1296",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Standards Configuration",
                "description": "API security standards configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1297",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Policy Configuration",
                "description": "API security policy configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1298",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Awareness Training Configuration",
                "description": "API security awareness training configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1299",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Governance Configuration",
                "description": "API security governance configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1300",
                "severity": "High"
            },
            {
                "name": "Insecure API Security Risk Management Configuration",
                "description": "API security risk management configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1301",
                "severity": "High"
            },
            {
                "name": "Exploit Public-Facing Application",
                "description": "An attacker exploits a vulnerability in a public-facing application to gain unauthorized access, execute arbitrary code, or perform other malicious activities.",
                "cve_id": "CVE-2021-12345",  # Replace with the actual CVE ID if available
                "severity": "Critical"
            },
            {
                "name": "Insecure API Configuration",
                "description": "API configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1302",
                "severity": "High"
            },
            {
                "name": "Insecure API Deployment Configuration",
                "description": "API deployment configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1303",
                "severity": "High"
            },
            {
                "name": "Insecure API Runtime Configuration",
                "description": "API runtime configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1304",
                "severity": "High"
            },
            {
                "name": "Insecure API Development Configuration",
                "description": "API development configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1305",
                "severity": "High"
            },
            {
                "name": "Insecure API Testing Configuration",
                "description": "API testing configurations that expose sensitive data or functionality.",
                "cve_id": "CVE-2021-1306",
                "severity": "High"
            },
            {
                "name": "Credential Access (Steal Application Access Token)",
                "description": "The API allows token theft via insecure storage or transmission of bearer tokens.",
                "cve_id": "CVE-2022-31136",  # Example: GitHub token exposure
                "severity": "High"
            },
            {
                "name": "Persistence (Hijack Execution Flow)",
                "description": "Execution flow is hijacked using unsafe deserialization or malicious headers/scripts.",
                "cve_id": "CVE-2020-9484",  # Apache Tomcat deserialization flaw
                "severity": "High"
            },
            {
                "name": "Execution (Command Injection)",
                "description": "The API is vulnerable to OS command injection via unsanitized parameters.",
                "cve_id": "CVE-2021-21315",  # Node.js Command Injection
                "severity": "Critical"
            },
            {
                "name": "Insecure Deserialization",
                "description": "User input is deserialized without validation, allowing remote code execution.",
                "cve_id": "CVE-2017-9805",  # Apache Struts deserialization
                "severity": "Critical"
            }
            
        ]

        
        # Loop through the vulnerabilities data and insert or update records
        for data in vulnerabilities_data:
            # Use update_or_create to handle duplicates based on cve_id
            cve_id_qs = GroundTruthVulnerability.objects.filter(cve_id=data['cve_id']).last()
            
            if cve_id_qs:
                # If the CVE ID already exists, update the record
                GroundTruthVulnerability.objects.filter(cve_id=data['cve_id']).update(
                    name = data['name'],
                    description = data['description'],
                    severity = data['severity'],
                )
                
            name_qs = GroundTruthVulnerability.objects.filter(name=data['name']).last()
            
            if name_qs:
                # If the CVE ID already exists, update the record
                GroundTruthVulnerability.objects.filter(name=data['name']).update(
                    name = data['name'],
                    description = data['description'],
                    severity = data['severity'],
                )
            else:
                
                GroundTruthVulnerability.objects.update_or_create(
                    cve_id=data['cve_id'],
                    name = data['name'],
                    defaults={
                        'name': data['name'],
                        'description': data['description'],
                        'severity': data['severity'],
                    }
                )

        # Print success message
        self.stdout.write(self.style.SUCCESS(f'Successfully added/updated Ground Truth Vulnerabilities.'))
