"""
Unit tests for the Flask application.
"""

import unittest
import json
from app import app


class FlaskAppTestCase(unittest.TestCase):
    """Test cases for the Flask application."""

    def setUp(self):
        """Set up test client."""
        self.app = app.test_client()
        self.app.testing = True

    def test_hello_world(self):
        """Test the hello world endpoint."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Hello, World!')
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['version'], '1.0.0')

    def test_health_check(self):
        """Test the health check endpoint."""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(data['service'], 'flask-app')

    def test_nonexistent_endpoint(self):
        """Test that nonexistent endpoints return 404."""
        response = self.app.get('/nonexistent')
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
