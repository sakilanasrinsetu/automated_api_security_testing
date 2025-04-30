from django.urls import reverse
from rest_framework.test import APITestCase
from api_scanner.models import APITest, SecurityTestCase
from user.models import UserAccount

class APITestExecuteTestCase(APITestCase):
    def setUp(self):
        self.user = UserAccount.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
        self.api_test = APITest.objects.create(
            name="Test API",
            endpoint="https://api.example.com/test",
            http_method="GET",
            created_by=self.user
        )
        self.test_case = SecurityTestCase.objects.create(
            name="Test Case",
            api_test=self.api_test,
            payload={},
            expected_response=""
        )

    def test_execute_api_test(self):
        url = reverse('api-test-execute', kwargs={'slug': self.api_test.slug})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data['detail'], "Started execution of 1 test cases")
        
    def test_execute_no_test_cases(self):
        self.test_case.delete()
        url = reverse('api-test-execute', kwargs={'slug': self.api_test.slug})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['detail'], "No test cases found for this API")