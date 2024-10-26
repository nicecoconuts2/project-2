import requests
import unittest

class TestJWKSClient(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def test_auth_valid(self):
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        self.assertIn("eyJ", response.text)  # Check if the response contains a JWT

    def test_auth_invalid(self):
        response = requests.post(f"{self.BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("eyJ", response.text)  # Ensure you get an expired token

    def test_jwks(self):
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        keys = response.json().get("keys", [])
        self.assertGreater(len(keys), 0)  # Ensure there are keys returned

if __name__ == "__main__":
    unittest.main()
