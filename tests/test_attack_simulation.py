from django.urls import reverse
from rest_framework.test import APITestCase
from api_scanner.models import APITest, SecurityTestCase

class AttackSimulationTestCase(APITestCase):
    def setUp(self):
        self.user = UserAccount.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
        self.api_test = APITest.objects.create(
            name="Vulnerable API",
            endpoint="https://api.example.com/v1",
            http_method="POST",
            created_by=self.user
        )
        self.high_severity_case = SecurityTestCase.objects.create(
            name="SQL Injection",
            severity="High",
            api_test=self.api_test,
            payload={"query": "1' OR '1'='1"},
            expected_response=""
        )

    def test_simulate_attack(self):
        url = reverse('api-test-simulate-attack', kwargs={'slug': self.api_test.slug})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 202)
        self.assertIn("Started 1 attack simulations", response.data['detail'])

    def test_simulate_attack_no_cases(self):
        self.high_severity_case.delete()
        url = reverse('api-test-simulate-attack', kwargs={'slug': self.api_test.slug})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 400)
        self.assertIn("No high-severity test cases", response.data['detail'])