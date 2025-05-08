import os
import random
import string
import time
from django.utils.text import slugify
import re

from api_scanner.models import *
from evaluation.models import *
from django.core.exceptions import ObjectDoesNotExist
import logging

logger = logging.getLogger(__name__)


from django.core.exceptions import ValidationError
from rest_framework.exceptions import ValidationError as DRFValidationError


def random_string_generator(size=4, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def random_number_generator(size=4, chars='1234567890'):
    return ''.join(random.choice(chars) for _ in range(size))


# def unique_slug_generator():
#     timestamp_m = time.strftime("%Y")
#     timestamp_d = time.strftime("%m")
#     timestamp_y = time.strftime("%d")
#     timestamp_now = time.strftime("%H%M%S")
#     random_str = random_string_generator()
#     random_num = random_number_generator()
#     bindings = (
#         random_str + timestamp_d + random_num + timestamp_now +
#         timestamp_y + random_num + timestamp_m
#     )
#     return bindings

def unique_slug_generator(name):
    timestamp_m = time.strftime("%Y")
    timestamp_d = time.strftime("%m")
    timestamp_y = time.strftime("%d")
    timestamp_now = time.strftime("%H%M%S")
    random_str = random_string_generator()
    random_num = random_number_generator() 
    bindings = f"{random_str}-{timestamp_d}-{random_num}-{timestamp_m}-{timestamp_now}-{timestamp_y}-{random_num}"
    
    slug = bindings
    
    if name:
        cleaned_name = re.sub(r'[^a-zA-Z0-9\s]', '', name) 
        
        converted_name = cleaned_name.lower().replace(' ', '-')
        slug = f"{converted_name}-{bindings}" 
    return slug


def unique_slug_generator_for_product_category(name):
    if name:
        # Remove non-alphanumeric characters except spaces
        cleaned_name = re.sub(r'[^a-zA-Z0-9\s]', '', name)
        # Convert to lowercase and replace spaces with hyphens
        converted_name = cleaned_name.lower().replace(' ', '-')
        slug = f"{converted_name}"
    else:
        slug = ""
        
    return slug

def generate_requisition_no(last_requisition_no):
    prefix = 'REG000'
    last_requisition_no = last_requisition_no.replace('REG000', '')
    if len(last_requisition_no) < 9:
        random_num = random.randint(10000, 99999)
    else:
        random_num = last_requisition_no
    
    random_num = int(random_num)+1
    new_requisition_no = f"{prefix}{random_num}"
    
    return new_requisition_no

def generate_invoice_no(last_invoice_no):
    prefix = 'ONL00'
    last_invoice_no = last_invoice_no.replace('ONL00', '')
    
    if len(last_invoice_no) < 9:
        random_num = random.randint(1000000, 9999999)
    else:
        random_num = last_invoice_no
    
    random_num = int(random_num) + 1
    new_invoice_no = f"{prefix}{random_num}"
    
    return new_invoice_no

def generate_service_invoice_no(last_invoice_no):
    prefix = 'SER00'
    last_invoice_no = last_invoice_no.replace('SER00', '')
    
    if len(last_invoice_no) < 10:
        random_num = random.randint(1000000, 9999999)
    else:
        random_num = last_invoice_no
    
    random_num = int(random_num) + 1
    new_invoice_no = f"{prefix}{random_num}"
    
    return new_invoice_no


def generate_transaction_number(last_transaction_no):
    prefix = 'OSL'
    
    # Remove any prefix like 'OSL00' from last_transaction_no
    last_transaction_no = last_transaction_no.replace('OSL00', '')
    
    # Check if the remaining string is shorter than 7 characters
    if len(last_transaction_no) < 10:
        random_num = random.randint(1000000, 9999999)
    else:
        try:
            random_num = int(last_transaction_no)
        except ValueError:
            random_num = random.randint(1000000, 9999999)
    
    random_num += 1
    new_invoice_no = f"{prefix}{random_num}"
    
    return new_invoice_no




# def generate_transaction_number(last_transaction_no):
#     prefix = 'OSL'
#     last_transaction_no = last_transaction_no.replace('OSL00', '')
    
#     if len(last_transaction_no) < 10:
#         random_num = random.randint(1000000, 9999999)
#     else:
#         random_num = last_transaction_no
    
#     random_num = int(random_num) + 1
#     new_invoice_no = f"{prefix}{random_num}"
    
#     return new_invoice_no

def generate_task_no(task_no):
    prefix = 'TASK000'
    task_no = task_no.replace('TASK000', '')
    if len(task_no) < 9:
        random_num = random.randint(10000, 99999)
    else:
        random_num = task_no
    
    random_num = int(random_num)+1
    new_task_no = f"{prefix}{random_num}"
    
    return new_task_no




# ............API Vulnerability Detection............


def detect_vulnerability(request_body: dict):
    try:
        api_test_slug = request_body.get("api_test")
        if not api_test_slug:
            raise ValueError("api_test key is required in the request body.")

        # Fetch the API test based on the slug
        api_test_qs = APITest.objects.filter(slug=api_test_slug).last()
        
        if not api_test_qs:
            raise ValueError(f"API Test with slug '{api_test_slug}' does not exist.")

        # Get all the associated security test cases for the given API test
        security_test_cases = api_test_qs.security_test_cases.all()
        
        if not security_test_cases:
            logger.info(f"No security test cases found for API test '{api_test_slug}'.")
            return {"message": "No security test cases associated with this API test."}

        detected_vulnerabilities = []
        
        
        # Iterate through security test cases and detect vulnerabilities based on MITRE ATT&CK techniques
        for security_test_case in security_test_cases:
            technique = security_test_case.mitre_attack_technique
            
            if technique:
                vulnerability_score = technique.severity_weight
                vulnerability_description = f"Potential vulnerability detected in API Test '{api_test_qs.name}' using technique '{technique.name}' (Risk Score: {vulnerability_score})"

                detected_vulnerabilities.append({
                    'technique': technique.name,
                    'severity': security_test_case.severity,
                    'score': vulnerability_score,
                    'description': vulnerability_description,
                    'security_test_case': security_test_case  # Add the security test case instance here
                })
                

        # Store detected vulnerabilities in the API Test execution (creating a TestExecution record)
        for vulnerability in detected_vulnerabilities:
            # Now, you can access the security_test_case from the vulnerability dictionary
            test_execution_qs = TestExecution.objects.create(
                api_test=api_test_qs,
                slug=f"exec-{api_test_slug}-{uuid.uuid4().hex[:10]}",
                success=True if detected_vulnerabilities else False,
                security_test_case=vulnerability['security_test_case'],  # Access security_test_case correctly
            )

            # Now create DetectionResult for each vulnerability detected
            
            ground_truth_vulnerability_qs = GroundTruthVulnerability.objects.filter(name__icontains=vulnerability['technique']).last()
            
            print(f"...........***.............., {vulnerability['technique']}, {ground_truth_vulnerability_qs}")
            
            qs = DetectionResult.objects.create(
                vulnerability=ground_truth_vulnerability_qs,
                detected=True,
                confidence_score=vulnerability['score'], 
                scanner_name="My Scanner",
            )
            
            print(f"............*****.............., {detected_vulnerabilities}")

        # Log successful vulnerability detection
        logger.info(f"Vulnerabilities detected for API Test '{api_test_slug}'.")

        return detected_vulnerabilities

    except APITest.DoesNotExist:
        logger.error(f"API Test with slug '{api_test_slug}' does not exist.")
        return {"error": f"API Test with slug '{api_test_slug}' does not exist."}
    except ValueError as e:
        logger.error(f"Invalid request body: {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {"error": "An unexpected error occurred while detecting vulnerabilities."}
    
    
        
def create_security_test_case(request_body, api_test_qs, vulnerability):
    """
    Function to create and associate a new security test case with an API test based on the provided request body and vulnerability.
    """
    try:

        # Extract the technique slug (this is likely in the vulnerability data)
        mitre_attack_technique_slug = vulnerability.get("technique")
        
        if not mitre_attack_technique_slug:
            raise ValueError("mitre_attack_technique_slug is required in the vulnerability data.")

        print(f"Looking for MITRE ATT&CK technique with slug: {mitre_attack_technique_slug}")

        # Fetch the technique associated with the provided slug
        mitre_attack_technique_qs = MITREAttackTechnique.objects.filter(name=mitre_attack_technique_slug).last()
        
        print(f"Fetched MITRE ATT&CK technique: {mitre_attack_technique_qs}")
        
        if not mitre_attack_technique_qs:
            raise ValueError(f"MITRE ATT&CK technique '{mitre_attack_technique_slug}' not found.")

        # Default values for the security test case
        severity = vulnerability.get("severity", "Low")  # Default to "Low" if not provided
        payload = vulnerability.get("payload", {})  # Default empty dictionary if no payload is provided
        expected_response = vulnerability.get("expected_response", "")  # Default empty string if not provided
        description = vulnerability.get("description", "No description provided.")  # Default description
        
        print(f".........***........... {mitre_attack_technique_qs}")

        # Create the security test case
        security_test_case = SecurityTestCase.objects.create(
            name=f"Security test for {api_test_qs.name}",
            slug=f"security-{api_test_qs.slug}-{uuid.uuid4().hex[:10]}",  # Generate a unique slug
            mitre_attack_technique=mitre_attack_technique_qs,
            api_test=api_test_qs,
            severity=severity,
            payload=payload,
            expected_response=expected_response,
            description=description
        )

        # Return the created test case details
        return security_test_case

    except ValueError as e:
        raise ValueError(f"Validation error: {str(e)}")

    except MITREAttackTechnique.DoesNotExist:
        raise Exception(f"MITRE ATT&CK technique not found for slug: {mitre_attack_technique_slug}")

    except Exception as e:
        raise Exception(f"An unexpected error occurred while creating the test case: {str(e)}")

