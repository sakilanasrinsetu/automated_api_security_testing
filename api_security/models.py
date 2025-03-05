from django.db import models
from user.models import UserAccount

# Constants
HTTP_METHOD = [
    ('GET', 'Get'),
    ('POST', 'Post'),
    ('PATCH', 'Patch'),
    ('DELETE', 'Delete'),
    ('PUT', 'Put'),
    ('HEAD', 'Head'),
    ('OPTIONS', 'Options'),
    ('TRACE', 'Trace'),
    ('CONNECT', 'Connect'),
]

AUTH_TYPE = [
    ('None', 'None'),
    ('Basic', 'Basic'),
    ('Bearer', 'Bearer'),
    ('API Key', 'API Key'),
    ('OAuth2', 'OAuth2'),
    ('JWT', 'JWT'),
]

SEVERITY_TYPE = [
    ('Low', 'Low'),
    ('Medium', 'Medium'),
    ('High', 'High'),
    ('Critical', 'Critical'),
    ('Unknown', 'Unknown'),
    ('Undetermined', 'Undetermined'),
    ('Not Specified', 'Not Specified'),
    ('Not Applicable', 'Not Applicable'),
]

API_LOG_STATUS = [
    ('Success', 'Success'),
    ('Failure', 'Failure'),
    ('Error', 'Error'),
    ('Warning', 'Warning'),
]

TEST_SCHEDULE_STATUS = [
    ('Pending', 'Pending'),
    ('Completed', 'Completed'),
    ('Failed', 'Failed'),
    ('Running', 'Running'),
    ('Skipped', 'Skipped'),
    ('Interrupted', 'Interrupted'),
    ('Not Run', 'Not Run'),
    ('Not Applicable', 'Not Applicable'),
    ('Blocked', 'Blocked'),
]

# MITRE ATT&CK Models for Tactics and Techniques
class MITREAttackTactic(models.Model):
    slug = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class MITREAttackTechnique(models.Model):
    slug = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    tactic = models.ForeignKey(MITREAttackTactic, on_delete=models.CASCADE, related_name='techniques')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


# API Test Models
class APITest(models.Model):
    name = models.CharField(max_length=255, unique=True)
    slug = models.CharField(max_length=255, unique=True)
    endpoint = models.URLField()
    http_method = models.CharField(max_length=10, choices=HTTP_METHOD, default="GET")
    headers = models.JSONField(blank=True, null=True)
    body = models.JSONField(blank=True, null=True)
    auth_type = models.CharField(max_length=20, choices=AUTH_TYPE, default='None')
    auth_credentials = models.JSONField(blank=True, null=True)
    created_by = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="created_by_api_tests")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class SecurityTestCase(models.Model):
    name = models.CharField(max_length=255)
    slug = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    mitre_attack_technique = models.ForeignKey(MITREAttackTechnique, on_delete=models.CASCADE, related_name='security_test_cases')
    severity = models.CharField(max_length=20, choices=SEVERITY_TYPE, default='Low')
    payload = models.JSONField()
    expected_response = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.mitre_attack_technique.name}"


class TestExecution(models.Model):
    api_test = models.ForeignKey(APITest, on_delete=models.CASCADE, related_name='test_executions')
    slug = models.CharField(max_length=255, unique=True)
    security_test_case = models.ForeignKey(SecurityTestCase, on_delete=models.CASCADE, related_name='test_executions')
    executed_by = models.ForeignKey(UserAccount, on_delete=models.SET_NULL, null=True, related_name="test_executions")
    executed_at = models.DateTimeField(auto_now_add=True)
    status_code = models.IntegerField()
    response_body = models.JSONField()
    detected_vulnerabilities = models.JSONField(blank=True, null=True)  # LLM-generated vulnerabilities
    success = models.BooleanField(default=False)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Test on {self.api_test.name} - {self.security_test_case.name}"


class LLMAnalysis(models.Model): 
    test_execution = models.ForeignKey(TestExecution, on_delete=models.CASCADE, related_name='llm_analysis')
    slug = models.CharField(max_length=255, unique=True)
    analysis_result = models.TextField()
    risk_score = models.IntegerField(default=0)  # 0-100 Risk Score
    mitigation_suggestions = models.TextField()
    security_controls = models.TextField(blank=True, null=True)  # Optional security controls related to the vulnerabilities
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"LLM Analysis for {self.test_execution}"


class Report(models.Model): 
    test_execution = models.ForeignKey(TestExecution, on_delete=models.CASCADE, related_name='reports')
    slug = models.CharField(max_length=255, unique=True)
    summary = models.TextField()
    recommendations = models.TextField()
    generated_by = models.ForeignKey(UserAccount, on_delete=models.SET_NULL, null=True, related_name='reports')
    generated_at = models.DateTimeField(auto_now_add=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Report for {self.test_execution}"


class AttackSimulation(models.Model): 
    api_test = models.ForeignKey(APITest, on_delete=models.CASCADE, related_name="attack_simulations")
    slug = models.CharField(max_length=255, unique=True)
    security_test_case = models.ForeignKey(SecurityTestCase, on_delete=models.CASCADE, related_name="attack_simulations")
    executed_by = models.ForeignKey(UserAccount, on_delete=models.SET_NULL, null=True, related_name="attack_simulations")
    executed_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField()
    impact_description = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Simulation on {self.api_test.name} - {self.security_test_case.name}"


class APILog(models.Model): 
    api_test = models.ForeignKey(APITest, on_delete=models.CASCADE, related_name='api_logs')
    slug = models.CharField(max_length=255, unique=True)
    attempted_by = models.ForeignKey(UserAccount, on_delete=models.SET_NULL, null=True, blank=True, related_name='api_logs')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=API_LOG_STATUS, default='Failure')
    response_code = models.IntegerField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Log for {self.api_test.name} - {self.status}"


class TestSchedule(models.Model): 
    api_test = models.ForeignKey(APITest, on_delete=models.CASCADE, related_name="test_schedules")
    slug = models.CharField(max_length=255, unique=True)
    security_test_case = models.ForeignKey(SecurityTestCase, on_delete=models.CASCADE, related_name="test_schedules")
    scheduled_by = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="test_schedules")
    schedule_time = models.DateTimeField()
    status = models.CharField(max_length=20, choices=TEST_SCHEDULE_STATUS, default='Pending')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Scheduled Test: {self.api_test.name} - {self.security_test_case.name}"
