from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from api_scanner.models import *
from api_scanner.serializers import *
from django.db import transaction
from evaluation.models import GroundTruthVulnerability
from evaluation.serializers import DetectionResultSerializer
from utils.permissions import IsAuthenticated

from utils.custom_veinlet import CustomViewSet
from utils.response_wrapper import ResponseWrapper
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, viewsets, filters

from utils.decorators import log_activity
from utils.generates import create_security_test_case, detect_vulnerability, unique_slug_generator


from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from django.http import FileResponse
import io
from django.core.files.base import ContentFile
from io import BytesIO


class MITREAttackTacticViewSet(CustomViewSet):
    queryset = MITREAttackTactic.objects.all()
    lookup_field = 'slug'
    serializer_class = MITREAttackTacticSerializer
    permission_classes = [permissions.IsAuthenticated]

class MITREAttackTechniqueViewSet(CustomViewSet):
    queryset = MITREAttackTechnique.objects.all()
    lookup_field = 'slug'
    serializer_class = MITREAttackTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated]

class APITestViewSet(CustomViewSet):
    queryset = APITest.objects.all().order_by('name')
    lookup_field = 'slug'
    serializer_class = APITestSerializer
    permission_classes = [permissions.IsAuthenticated]

    
    def create(self, request, *args, **kwargs):
        # Step 1: Handle APITest Creation
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.data, partial=True)
        name = ''

        if request.data.get('name'):
            name = request.data.get('name')

        try:
            qs = self.queryset.filter(name=name)
            if qs:
                return ResponseWrapper(error_msg="Name is Already Found", error_code=400)
        except:
            pass

        if not serializer.is_valid():
            return ResponseWrapper(error_msg=serializer.errors, error_code=400)

        # Generate Slug
        if name:
            slug = unique_slug_generator(name=name)
        try:
            serializer.validated_data['slug'] = slug
        except:
            pass

        serializer.validated_data['created_by'] = request.user

        # Step 2: Save APITest instance
        try:
            qs = serializer.save()
            if slug:
                qs.slug = slug
                qs.save()
        except:
            qs = serializer.save()

        # Step 3: Create Related SecurityTestCase and TestExecution (if provided)
        print(f"# === APITest Created: {request.data.get('vulnerability') and request.data.get('mitre_attack_technique')} ===")
        
        
        if request.data.get('vulnerability') and request.data.get('mitre_attack_technique'):
            # Step 3.1: Create SecurityTestCase
            vulnerability_name = request.data.get('vulnerability')
            mitre_attack_technique_id = request.data.get('mitre_attack_technique')
            cve_id = request.data.get('cve_id', '')

            # Check if MITREAttackTechnique exists
            mitre_attack_technique = MITREAttackTechnique.objects.filter(mitre_attack_technique_id=mitre_attack_technique_id).first()
            if not mitre_attack_technique:
                return ResponseWrapper(error_msg="Invalid MITRE Attack Technique", error_code=400)

            # Create SecurityTestCase
            security_test_case = SecurityTestCase.objects.create(
                name=f"{vulnerability_name} - {mitre_attack_technique.name}",
                slug=unique_slug_generator(f"{vulnerability_name} - {mitre_attack_technique.name}"),
                description=f"Test case for {vulnerability_name}",
                mitre_attack_technique=mitre_attack_technique,
                api_test=qs,
                severity="High",  # Assuming High severity for this example, can be dynamic
                payload={
                    "vulnerability": vulnerability_name,
                    "cve_id": cve_id
                },
                expected_response="500 Internal Server Error"  # Can be dynamic or based on the vulnerability
            )
            
            print(f"# === Security Test Case Created: {security_test_case.name} ===")

            # Step 3.2: Create TestExecution
            TestExecution.objects.create(
                api_test=qs,
                security_test_case=security_test_case,
                slug=f"exec-{uuid.uuid4().hex[:10]}",  # Unique slug for execution
                executed_by=request.user,
                success=False,  # Default to False, can be updated later
                status='queued',  # Initial status
            )

        return ResponseWrapper(data=serializer.data, msg='created', status=200)


class SecurityTestCaseViewSet(CustomViewSet):
    queryset = SecurityTestCase.objects.all().order_by('name')
    lookup_field = 'slug'
    serializer_class = SecurityTestCaseSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action in ['create', "update"]:
            self.serializer_class = SecurityTestCaseCreateSerializer
        else:
            self.serializer_class = SecurityTestCaseSerializer

        return self.serializer_class
    
    def create(self, request, *args, **kwargs):
        try:
            # Step 1: Retrieve the API test using the provided slug
            api_test_slug = request.data.get('api_test')
            if not api_test_slug:
                return ResponseWrapper(data=None, msg="api_test is required.", status=400)
            
            # Retrieve the API test by slug
            api_test_qs = APITest.objects.filter(slug=api_test_slug).last()

            if not api_test_qs:
                return ResponseWrapper(data=None, msg="API test not found.", status=404)

            # Step 2: Detect vulnerabilities in the given API test (auto-detection)
            vulnerabilities = detect_vulnerability(request.data)  # Ensure this returns the correct structure

            if not vulnerabilities:
                return ResponseWrapper(data=None, msg="No vulnerabilities detected.", status=404)

            # Step 3: Create security test cases for each detected vulnerability
            created_test_cases = []
            for vulnerability in vulnerabilities:
                if vulnerability:
                    try:
                        # Make sure vulnerability contains the correct data
                        
                        print(f"# === Creating Security Test Case for Vulnerability: {vulnerabilities} ===")
                        security_test_case = create_security_test_case(request.data, api_test_qs, vulnerability)
                        
                        print(f"# === Security Test Case Created: {security_test_case.name} ===")
                        
                        created_test_cases.append(security_test_case)
                    except Exception as e:
                        # Handle individual vulnerability creation errors
                        return ResponseWrapper(data=None, msg=f"Error creating test case: {str(e)}", status=400)
                else:
                    return ResponseWrapper(data=None, msg="Invalid vulnerability detected.", status=400)

            # Step 4: Serialize the created security test cases
            serializer = SecurityTestCaseSerializer(created_test_cases, many=True)

            # Return a success response with the serialized data
            return ResponseWrapper(data=serializer.data, msg="Success", status=200)

        except Exception as e:
            # General error handling
            return ResponseWrapper(data=None, msg=str(e), status=500)
    

class TestExecutionViewSet(CustomViewSet):
    queryset = TestExecution.objects.all()
    lookup_field = 'slug'
    serializer_class = TestExecutionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    
    def get_detected_vulnerabilities(self, test_case):
        """
        Fetch the detected vulnerabilities for the provided TestExecution instance.
        This assumes that the detected vulnerabilities are stored in the 'detected_vulnerabilities' field.
        """
        test_execution = TestExecution.objects.filter(security_test_case=test_case).last()
        return test_execution.detected_vulnerabilities
    
    def generate_summary(self, test_case):
        """
        Generates a detailed summary for the report, including detected vulnerabilities, attack techniques, and overall test results.
        """
        print(f"# === Generating Summary for Test Case: {test_case.name} ===")
        
        vulnerabilities = self.get_detected_vulnerabilities(test_case)
        attack_technique = test_case.mitre_attack_technique
        # llm_analysis = test_case.llm_analysis  # Assuming LLM analysis is associated with test_case

        # Start with basic test execution info
        summary = f"Test execution for {vulnerabilities} has been completed. "
        
        if vulnerabilities:
            # Detected vulnerabilities section
            detected_vulns = [f"{v['vulnerability']} (Risk Score: {v['risk_score']})" for v in vulnerabilities]
            summary += f"The following vulnerabilities were detected: {', '.join(detected_vulns)}. "
        else:
            summary += "No vulnerabilities were detected. "
        
        if attack_technique:
            summary += f"MITRE ATT&CK technique used: {attack_technique.name}. "
            
            
        test_execution = test_case.test_executions.last() 
        
        llm_analysis = test_execution.llm_analyses.last()
        
        print(f"# === LLM Analysis: {llm_analysis} ===")
        
        if llm_analysis:
            summary += f"\n\n LLM analysis indicates a risk level of {test_execution.llm_analyses.last().risk_score} for the detected vulnerability. "
            print(f"# === Summary Generated: {summary} ===")

        summary += f"\n\n The overall test execution status is: {test_execution.llm_analyses.last().result_type}."
        
        print(f"# === Summary Generated: {summary} ===")   

        return summary

    def generate_recommendations(self, test_case):
        """
        Generates detailed recommendations based on the detected vulnerabilities and their risk levels.
        """
        vulnerabilities = self.get_detected_vulnerabilities(test_case)
        recommendations = []

        if vulnerabilities:
            for vuln in vulnerabilities:
                # For each detected vulnerability, suggest recommendations
                vuln_name = vuln['vulnerability']
                risk_score = vuln['risk_score']
                
                if risk_score >= 7.5:
                    recommendations.append(f"High severity vulnerability '{vuln_name}' detected. Immediate action is recommended, such as applying patches and enhancing input validation.")
                elif risk_score >= 4.5:
                    recommendations.append(f"Medium severity vulnerability '{vuln_name}' detected. Mitigation should be prioritized, focusing on secure coding practices and testing for potential exploits.")
                elif risk_score >= 2.5:
                    recommendations.append(f"Low severity vulnerability '{vuln_name}' detected. Monitoring and occasional reviews should be sufficient for this risk.")
                else:
                    recommendations.append(f"Unknown vulnerability '{vuln_name}' detected. Further investigation is needed to confirm the impact and potential mitigation steps.")
        
        # Additional general recommendations based on MITRE ATT&CK or LLM analysis
        if test_case.mitre_attack_technique:
            recommendations.append(f"Consider reviewing the attack vector: {test_case.mitre_attack_technique.name}, and implement recommended security controls.")
        
        test_execution = test_case.test_executions.last() 
        
        llm_analysis = test_execution.llm_analyses.last()
        
        if llm_analysis:
            recommendations.append(f"\n\nBased on LLM analysis, consider reviewing the high-risk areas indicated by the model, such as improper input validation or SQL injection risks.")
            
            
        print(f"# === Recommendations Generated: {recommendations} ===")
        
        return " ".join(recommendations)

    def get_severity_from_mitre_and_llm(self, test_case):
        """
        Helper method to determine the severity level of a vulnerability based on MITRE ATT&CK and LLM analysis.
        This method checks the attack technique and any additional insights from LLM to classify the severity.
        """
        mitre_attack_technique = test_case.mitre_attack_technique
        test_execution = test_case.test_executions.last() 
        
        llm_analysis = test_execution.llm_analyses.last()  # Assuming LLM analysis is associated with test_case

        if mitre_attack_technique and llm_analysis:
            # If the LLM analysis suggests a high risk, we override with that
            if llm_analysis.risk_score >= 7.5:
                return "High"
            elif llm_analysis.risk_score >= 4.5:
                return "Medium"
            elif llm_analysis.risk_score >= 2.5:
                return "Low"
            else:
                return "Unknown"
        
        # If there's no LLM analysis, determine severity from MITRE ATT&CK technique alone
        if mitre_attack_technique:
            if mitre_attack_technique.severity == "Critical":
                return "Critical"
            elif mitre_attack_technique.severity == "High":
                return "High"
            elif mitre_attack_technique.severity == "Medium":
                return "Medium"
            elif mitre_attack_technique.severity == "Low":
                return "Low"
            else:
                return "Not Specified"
        
        return "Undetermined" 

    @transaction.atomic
    def api_test_execute(self, request, api_test_slug):
        api_test = APITest.objects.filter(slug=api_test_slug).last()
        if not api_test:
            return ResponseWrapper(error_msg="API Test not found.", error_code=404)

        security_test_cases = SecurityTestCase.objects.filter(api_test=api_test)
        if not security_test_cases.exists():
            return ResponseWrapper(error_msg="No Security Test Cases found.", error_code=404)

        results = []

        for test_case in security_test_cases:
            
            try:
                # === 1. Test Execution ===
                execution_data = {
                    'slug': unique_slug_generator(name=f"{api_test.name}-{test_case.name}"),
                    'api_test': api_test.id,
                    'security_test_case': test_case.id,
                    'executed_by': request.user.id,
                    'response_body': {"response": "Sample output"},
                    'detected_vulnerabilities': [{"vulnerability": "SQL Injection", "risk_score": 8.5}],
                    'success': False,
                    'remarks': "SQL Injection detected",
                    'status_code': 200,
                    'status': "completed",
                    'execution_parameters': {}
                }
                execution_serializer = TestExecutionSerializer(data=execution_data)
                execution_serializer.is_valid(raise_exception=True)
                test_execution = execution_serializer.save()
                
                print(f"# === 1. Test Execution Done ===")

                # === 2. Trigger LLM Analysis ===
                llm_data = {
                    'slug': unique_slug_generator(name=f"{test_case.name}-LLM"),
                    'test_execution': test_execution.slug,
                    'analysis_result': "SQLi detected",
                    'mitigation_suggestions': "Use parameterized queries.",
                    'risk_score': 8.5,
                    'result_type': "High",
                    'security_controls': "Input validation, parameterized SQL"
                }
                llm_serializer = LLMAnalysisSerializer(data=llm_data)
                llm_serializer.is_valid(raise_exception=True)
                llm_serializer.save()
                
                print(f"# === 2. LLM Analysis Done ===")

                # === 3. Run Attack Simulation ===
                simulation_data = {
                    'slug': unique_slug_generator(name=f"{test_case.name}-Simulation"),
                    'api_test': api_test.slug,
                    'security_test_case': test_case.slug,
                    'executed_by': request.user,
                    'attack_vector': "SQL Injection via login",
                    'simulation_result': "Successful exploitation",
                    'success': True,
                    'impact_description': "Data leakage"
                }
                simulation_serializer = AttackSimulationSerializer(data=simulation_data)
                simulation_serializer.is_valid(raise_exception=True)
                simulation_serializer.save()
                
                print(f"# === 3. Attack Simulation Done ===")

                # === 4. Record API Log ===
                log_data = {
                    'slug': unique_slug_generator(name=f"{test_case.name}-Log"),
                    'api_test': api_test.slug,
                    'attempted_by': request.user.id,
                    'ip_address': request.META.get('REMOTE_ADDR'),
                    'user_agent': request.META.get('HTTP_USER_AGENT'),
                    'status': "Success",
                    'response_code': 200,
                    'actual_request_headers': {},
                    'actual_request_body': request.body.decode('utf-8'),
                    'response_time_ms': 150,
                }
                log_serializer = APILogSerializer(data=log_data)
                log_serializer.is_valid(raise_exception=True)
                log_serializer.save()
                
                print(f"# === 4. API Log Recorded ===")

                # === 5. Generate Detection Result ===
                # Reference an existing vulnerability from the GroundTruthVulnerability model
                vulnerability_qs = GroundTruthVulnerability.objects.filter(name="SQL Injection").first()
                
                # Ensure that vulnerability is found, else handle the error
                if not vulnerability_qs:
                    return ResponseWrapper(error_msg="Ground Truth Vulnerability not found for SQL Injection.", error_code=404)

                detection_data = {
                    'slug': unique_slug_generator(name=f"{test_case.name}-Detection"),
                    'test_execution': test_execution.slug,
                    'vulnerability': vulnerability_qs.id,  # Reference the GroundTruthVulnerability object
                    'detected':False,  # Provide a valid scanner name
                    'confidence_score': 0.0,
                    'scanner_name': "My Scanner",
                }
                detection_serializer = DetectionResultSerializer(data=detection_data)
                detection_serializer.is_valid(raise_exception=True)
                detection_serializer.save()
                
                print(f"# === 5. Detection Result Recorded ===")

                # === 6. Generate Report ===
                
                
                try:
                    summary = self.generate_summary(test_case)
                except Exception as e:
                    return ResponseWrapper(error_msg=f"Error generating summary: {str(e)}", error_code=500)

                try:
                    recommendations = self.generate_recommendations(test_case)
                except Exception as e:
                    return ResponseWrapper(error_msg=f"Error generating recommendations: {str(e)}", error_code=500)

                try:
                    risk_level = self.get_severity_from_mitre_and_llm(test_case)
                except Exception as e:
                    return ResponseWrapper(error_msg=f"Error calculating risk level: {str(e)}", error_code=500)

                report_data = {
                    'slug': unique_slug_generator(name=f"{test_case.name}-Report"),
                    'test_execution': test_execution.slug,
                    'summary': summary,
                    'recommendations': recommendations,
                    'generated_by__id': request.user.pk,
                    'risk_level': risk_level
                }
                
                print(f"# === 6. Generating Report === {report_data}")
                
                report_serializer = ReportSerializer(data=report_data)
                report_serializer.is_valid(raise_exception=True)
                report_serializer.save()
                
                print(f"# === 6. Report Generated ===")

                results.append(test_execution)

            except Exception as e:
                return ResponseWrapper(error_msg=f"Execution failed for {test_case.name}: {str(e)}", error_code=400)
            
        
        serialized = TestExecutionSerializer(results, many=True)
        return ResponseWrapper(data=serialized.data, msg="Execution complete", status=200)

    
    def test_executions_llm_analysis(self, request, test_execution_slug, *args, **kwargs):
        test_execution_qs = TestExecution.objects.filter(slug=test_execution_slug).last()
        if not test_execution_qs:
            return ResponseWrapper(error_msg="This Test Execution not found", error_code=404)
        
        llm_analysis_qs = LLMAnalysis.objects.filter(test_execution__slug=test_execution_qs.slug)
        
        if not llm_analysis_qs:
            return ResponseWrapper(error_msg=f"No LLM Analysis Found for {test_execution_qs.api_test.name}", error_code=404)
        
        serializer = LLMAnalysisSerializer(llm_analysis_qs, many=True)
        
        return ResponseWrapper(data=serializer.data, msg="LLM Analysis Found", status=200)
        
        
        
    # Generate a report
    @log_activity
    @transaction.atomic
    def test_executions_report(self, request, test_execution_slug, *args, **kwargs):
        test_execution_qs = TestExecution.objects.filter(slug=test_execution_slug).last()
        if not test_execution_qs:
            return ResponseWrapper(error_msg="This Test Execution not found", error_code=404)
        
        llm_analysis_qs = LLMAnalysis.objects.filter(test_execution__slug=test_execution_qs.slug)
        
        # Check if there is no LLM analysis
        if not llm_analysis_qs:
            return ResponseWrapper(error_msg=f"No LLM Analysis Found for {test_execution_qs.api_test.name}", error_code=404)

        # Create an in-memory file for the report
        report_io = io.BytesIO()

        # Create SimpleDocTemplate object with letter page size
        doc = SimpleDocTemplate(report_io, pagesize=letter)

        # Define styles
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        heading_style = styles['Heading1']

        # Title and header text
        content = []

        title = f"Security Test Report: {test_execution_qs.api_test.name}"
        content.append(Paragraph(title, heading_style))
        content.append(Spacer(1, 12))
        content.append(Paragraph(f"Test Execution: {test_execution_qs.slug}", normal_style))
        content.append(Paragraph(f"Executed By: {test_execution_qs.executed_by.username}", normal_style))
        content.append(Paragraph(f"Executed At: {test_execution_qs.executed_at}", normal_style))
        content.append(Spacer(1, 12))

        # Create the table headers
        data = [
            ["LLM Analysis Results", "", ""],  # Table header
            ["Analysis Result", "Risk Score", "Risk Type"],  # Column titles
        ]

        # Add data rows from LLM analysis queryset
        for result in llm_analysis_qs:
            # Check if result is valid
            if result.analysis_result and result.risk_score is not None:
                data.append([result.analysis_result, result.risk_score, result.result_type])
            else:
                # Handle missing data or invalid entries
                data.append(["No Data", "N/A", "N/A"])

        # Create the table
        table = Table(data)

        # Style the table (adding color, borders, alignment, etc.)
        style = TableStyle([
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ])

        table.setStyle(style)

        # Add the table to the content
        content.append(table)

        # Build the document
        doc.build(content)

        # Move the pointer to the beginning of the file
        report_io.seek(0)
        
        
        # Create and save the report model
        report = Report.objects.create(
            test_execution=test_execution_qs,
            slug=unique_slug_generator(name=test_execution_qs.api_test.name),
            summary="Summary of the test execution",
            recommendations="Recommendations based on the test execution",
            generated_by=request.user,
        )

        # Return the generated PDF report as a file response
        return FileResponse(report_io, as_attachment=True, filename=f"security_report_{test_execution_qs.api_test.name}.pdf")
    
    
    @log_activity
    @transaction.atomic
    def get_report(self, request, test_execution_slug, *args, **kwargs):
        """
        Retrieves the generated report for a specific test execution based on the provided slug.
        If no report exists, it generates one.
        """
        # Fetch the TestExecution object by slug
        test_execution_qs = TestExecution.objects.filter(slug=test_execution_slug).last()
        if not test_execution_qs:
            return ResponseWrapper(error_msg="Test Execution not found", error_code=404)

        # Check if a report already exists for this test execution
        existing_report = Report.objects.filter(test_execution=test_execution_qs).first()
        
        # If no report exists, generate a new one
        report_io = BytesIO()
        
        if existing_report:
            # If a report exists, return it
            return FileResponse(report_io, as_attachment=True, filename=f"security_report_{test_execution_qs.api_test.name}.pdf")

        doc = SimpleDocTemplate(report_io, pagesize=letter)
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        heading_style = styles['Heading1']

        # Initialize content for the PDF report
        content = []
        title = f"Security Test Report: {test_execution_qs.api_test.name}"
        content.append(Paragraph(title, heading_style))
        content.append(Spacer(1, 12))
        content.append(Paragraph(f"Test Execution: {test_execution_qs.slug}", normal_style))
        content.append(Paragraph(f"Executed By: {test_execution_qs.executed_by.username}", normal_style))
        content.append(Paragraph(f"Executed At: {test_execution_qs.executed_at}", normal_style))
        content.append(Spacer(1, 12))

        llm_analysis_qs = LLMAnalysis.objects.filter(test_execution=test_execution_qs)
        if llm_analysis_qs:
            # Add LLM Analysis data to the table
            data = [
                ["LLM Analysis Results", "", ""],  # Table header
                ["Analysis Result", "Risk Score", "Risk Type"],  # Column titles
            ]
            for result in llm_analysis_qs:
                data.append([result.analysis_result, result.risk_score, result.result_type])

            # Create and style the table
            table = Table(data)
            style = TableStyle([
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ])
            table.setStyle(style)
            content.append(table)

        doc.build(content)

        # Save the report to the filesystem
        report_io.seek(0)
        file_name = f"security_report.pdf"
        report_file = ContentFile(report_io.getvalue())


        # Return the generated report as a file response
        return FileResponse(report_io, as_attachment=True, filename=f"security_report_{test_execution_qs.api_test.name}.pdf")

class AttackSimulationViewSet(CustomViewSet):
    queryset = AttackSimulation.objects.all()
    lookup_field = 'slug'
    serializer_class = AttackSimulationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        serializer_class = self.get_serializer_class()
        
        serializer = serializer_class(data=request.data, partial=True)
        name = 'attack-simulation'
            
        if not serializer.is_valid():
            return ResponseWrapper(error_msg=serializer.errors, error_code=400)
        
        if name:
            slug = unique_slug_generator(name = name) 
            
        try:
            serializer.validated_data['slug'] = slug
        except:
            pass
        
        serializer.validated_data['executed_by'] = request.user
        
        try:
            qs = serializer.save()
            if slug:
                qs.slug = slug
                qs.save()
            
        except:
            qs = serializer.save()
        return ResponseWrapper(data=serializer.data, msg='created', status=201)



class ReportViewSet(CustomViewSet):
    queryset = Report.objects.all()
    lookup_field = 'slug'
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    
    def test_execution_report(self, request, api_test_slug, *args, **kwargs):
        report_test_execution_qs = Report.objects.filter(test_execution__api_test__slug=api_test_slug).last()
        
        if not report_test_execution_qs:
            return ResponseWrapper(error_msg="This Test Execution not Report is Not found", error_code=404)
        
        serializer = ReportSerializer(report_test_execution_qs)
        
        return ResponseWrapper(data=serializer.data, msg="Report Found", status=200)