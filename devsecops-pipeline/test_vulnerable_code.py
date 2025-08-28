"""
Unit tests for vulnerable_code.py

This test suite covers all the security-fixed functions and routes
to ensure they work correctly and maintain their security improvements.
"""

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import mock_open, patch

from vulnerable_code import app, vulnerable_file_handling, weak_password_hash


class TestVulnerableCode(unittest.TestCase):
    """Test cases for the security-fixed vulnerable code module."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app = app.test_client()
        self.app.testing = True

        # Set up environment variables for testing
        os.environ['DATABASE_PASSWORD'] = 'test_db_password'
        os.environ['SECRET_KEY'] = 'test_secret_key'
        os.environ['API_TOKEN'] = 'test_api_token'

        # Create a temporary database for testing
        self.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.test_db_path = self.test_db.name
        self.test_db.close()

        # Set up test database with sample data
        self._setup_test_database()

    def tearDown(self):
        """Clean up after each test method."""
        # Remove test database
        if os.path.exists(self.test_db_path):
            os.unlink(self.test_db_path)

        # Clean up environment variables
        for key in ['DATABASE_PASSWORD', 'SECRET_KEY', 'API_TOKEN']:
            if key in os.environ:
                del os.environ[key]

    def _setup_test_database(self):
        """Create and populate test database."""
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')

        # Insert test data
        cursor.execute(
            "INSERT INTO users (id, username, email) VALUES (?, ?, ?)",
            (1, "testuser", "test@example.com")
        )
        cursor.execute(
            "INSERT INTO users (id, username, email) VALUES (?, ?, ?)",
            (2, "admin", "admin@example.com")
        )

        conn.commit()
        conn.close()

    @patch('vulnerable_code.sqlite3.connect')
    def test_get_vulnerable_user_valid_id(self, mock_connect):
        """Test getting user with valid ID using parameterized query."""
        # Mock database connection and cursor
        mock_conn = mock_connect.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (1, "testuser", "test@example.com")

        response = self.app.get('/vulnerable-user?id=1')
        self.assertEqual(response.status_code, 200)
        self.assertIn("testuser", response.get_data(as_text=True))

        # Verify parameterized query was used
        mock_cursor.execute.assert_called_with(
            "SELECT * FROM users WHERE id = :id",
            {"id": "1"}
        )

    @patch('vulnerable_code.sqlite3.connect')
    def test_get_vulnerable_user_nonexistent_id(self, mock_connect):
        """Test getting user with non-existent ID."""
        # Mock database connection and cursor
        mock_conn = mock_connect.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        response = self.app.get('/vulnerable-user?id=999')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "User not found")

    @patch('vulnerable_code.sqlite3.connect')
    def test_get_vulnerable_user_sql_injection_attempt(self, mock_connect):
        """Test that SQL injection attempts are safely handled."""
        # Mock database connection and cursor
        mock_conn = mock_connect.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        # Attempt SQL injection
        malicious_input = "1; DROP TABLE users; --"
        response = self.app.get(f'/vulnerable-user?id={malicious_input}')
        self.assertEqual(response.status_code, 200)

        # Verify the malicious input is passed as a parameter, not concatenated
        mock_cursor.execute.assert_called_with(
            "SELECT * FROM users WHERE id = :id",
            {"id": malicious_input}
        )

    def test_vulnerable_greeting_normal_input(self):
        """Test greeting with normal user input."""
        response = self.app.get('/vulnerable-greeting?name=John')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(
            as_text=True), "<h1>Hello John!</h1>")

    def test_vulnerable_greeting_no_input(self):
        """Test greeting with no name parameter."""
        response = self.app.get('/vulnerable-greeting')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(
            as_text=True), "<h1>Hello World!</h1>")

    def test_vulnerable_greeting_xss_prevention(self):
        """Test that XSS attempts are properly escaped."""
        xss_payload = "<script>alert('XSS')</script>"
        response = self.app.get(f'/vulnerable-greeting?name={xss_payload}')
        self.assertEqual(response.status_code, 200)

        # Check that the script tags are escaped
        response_text = response.get_data(as_text=True)
        self.assertIn("&lt;script&gt;", response_text)
        self.assertIn("&lt;/script&gt;", response_text)
        self.assertNotIn("<script>", response_text)

    def test_vulnerable_greeting_html_injection_prevention(self):
        """Test that HTML injection is prevented."""
        html_payload = "<img src=x onerror=alert('XSS')>"
        response = self.app.get(f'/vulnerable-greeting?name={html_payload}')
        self.assertEqual(response.status_code, 200)

        response_text = response.get_data(as_text=True)
        # Check that HTML tags are escaped
        self.assertIn("&lt;img", response_text)
        self.assertNotIn("<img", response_text)

    def test_weak_password_hash_sha512(self):
        """Test that password hashing uses SHA-512."""
        password = "testpassword123"
        hashed = weak_password_hash(password)

        # Verify it's a SHA-512 hash (128 characters in hex)
        self.assertEqual(len(hashed), 128)

        # Verify it's actually SHA-512
        expected_hash = hashlib.sha512(password.encode()).hexdigest()
        self.assertEqual(hashed, expected_hash)

    def test_weak_password_hash_different_passwords(self):
        """Test that different passwords produce different hashes."""
        password1 = "password1"
        password2 = "password2"

        hash1 = weak_password_hash(password1)
        hash2 = weak_password_hash(password2)

        self.assertNotEqual(hash1, hash2)

    def test_weak_password_hash_consistency(self):
        """Test that the same password always produces the same hash."""
        password = "consistent_password"

        hash1 = weak_password_hash(password)
        hash2 = weak_password_hash(password)

        self.assertEqual(hash1, hash2)

    def test_app_security_configuration(self):
        """Test that the app is configured securely."""
        # Test that debug mode is disabled in production
        self.assertFalse(app.debug)

        # Test that CSRF protection is enabled
        self.assertTrue(hasattr(app, 'extensions'))
        self.assertIn('csrf', app.extensions)


class TestSecurityImprovements(unittest.TestCase):
    """Additional tests to verify security improvements."""

    def test_no_hardcoded_secrets_in_source(self):
        """Test that no hardcoded secrets are present in the source code."""
        # Read the source file
        with open('vulnerable_code.py', 'r') as f:
            source_code = f.read()

        # Check that sensitive values are loaded from environment
        self.assertIn('os.getenv("DATABASE_PASSWORD")', source_code)
        self.assertIn('os.getenv("SECRET_KEY")', source_code)
        self.assertIn('os.getenv("API_TOKEN")', source_code)

        # Ensure no hardcoded passwords or keys
        sensitive_patterns = ['password123', 'secret123', 'admin123']
        for pattern in sensitive_patterns:
            self.assertNotIn(pattern.lower(), source_code.lower())

    def test_sql_injection_protection(self):
        """Test that parameterized queries are used."""
        with open('vulnerable_code.py', 'r') as f:
            source_code = f.read()

        # Check for parameterized query pattern
        self.assertIn('cursor.execute(query, {"id": user_id})', source_code)

        # Ensure no string concatenation in SQL queries
        self.assertNotIn('f"SELECT * FROM users WHERE id = {', source_code)
        self.assertNotIn('" + user_id + "', source_code)

    def test_xss_protection(self):
        """Test that XSS protection is implemented."""
        with open('vulnerable_code.py', 'r') as f:
            source_code = f.read()

        # Check that escape function is imported and used
        self.assertIn('from flask import Flask, escape', source_code)
        self.assertIn('escape(name)', source_code)


if __name__ == '__main__':
    unittest.main()
