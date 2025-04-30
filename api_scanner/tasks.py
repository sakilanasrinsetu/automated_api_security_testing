from celery import shared_task
from .models import TestExecution
import requests

from .models import AttackSimulation
from faker import Faker
import random
    
    
@shared_task(bind=True)
def execute_api_test(self, execution_id):
    execution = TestExecution.objects.get(id=execution_id)
    test_case = execution.security_test_case
    api_test = execution.api_test
    
    try:
        # Prepare request
        headers = api_test.headers or {}
        if api_test.auth_type == 'Bearer':
            headers['Authorization'] = f"Bearer {api_test.auth_credentials.get('token')}"
        
        # Execute the test
        response = requests.request(
            method=api_test.http_method,
            url=api_test.endpoint,
            headers=headers,
            json=test_case.payload,
            timeout=10
        )
        
        # Update execution record
        execution.status_code = response.status_code
        execution.response_headers = dict(response.headers)
        execution.response_body = response.json()
        execution.success = response.status_code < 400
        execution.save()
        
    except Exception as e:
        execution.remarks = str(e)
        execution.success = False
        execution.save()
        raise self.retry(exc=e, countdown=60)
    
    
@shared_task(bind=True)
def simulate_attack(self, simulation_id):
    
    fake = Faker()
    simulation = AttackSimulation.objects.get(id=simulation_id)
    
    try:
        # Simulate different attack scenarios based on test case
        test_case = simulation.security_test_case
        attack_type = test_case.mitre_attack_technique.name.lower()
        
        # Simulate attack (this would be your actual attack simulation logic)
        if 'injection' in attack_type:
            result = simulate_injection_attack(simulation.api_test)
        elif 'authentication' in attack_type:
            result = simulate_auth_attack(simulation.api_test)
        else:
            result = simulate_generic_attack(simulation.api_test)
        
        # Update simulation record
        simulation.success = result['success']
        simulation.impact_description = result.get('impact', fake.text())
        simulation.save()
        
    except Exception as e:
        simulation.impact_description = f"Attack failed: {str(e)}"
        simulation.success = False
        simulation.save()
        raise self.retry(exc=e, countdown=60)

def simulate_injection_attack(api_test):
    # Example SQL injection simulation
    return {
        'success': random.choice([True, False]),
        'impact': 'Potential SQL injection vulnerability detected'
    }

def simulate_auth_attack(api_test):
    # Example auth bypass simulation
    return {
        'success': random.choice([True, False]),
        'impact': 'Possible authentication bypass'
    }

def simulate_generic_attack(api_test):
    return {
        'success': random.choice([True, False]),
        'impact': 'Security anomaly detected'
    }
    
    
@shared_task(bind=True)
def execute_security_test_case(self, execution_id):
    execution = TestExecution.objects.get(id=execution_id)
    execution.status = 'running'
    execution.save()
    
    try:
        # Prepare request from execution parameters
        params = execution.execution_parameters
        test_case = execution.security_test_case
        api_test = execution.api_test
        
        # Execute the request
        response = requests.request(
            method=api_test.http_method,
            url=params.get('target_override', api_test.endpoint),
            headers=params.get('headers_override', api_test.headers or {}),
            json=params.get('payload_override', test_case.payload),
            timeout=10
        )
        
        # Update execution
        execution.status_code = response.status_code
        execution.response_body = response.json()
        execution.success = response.status_code < 400
        execution.status = 'completed'
        execution.save()
        
    except Exception as e:
        execution.status = 'failed'
        execution.remarks = str(e)
        execution.save()
        raise self.retry(exc=e, countdown=60)