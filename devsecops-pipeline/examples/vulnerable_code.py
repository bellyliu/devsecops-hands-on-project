"""
Example vulnerable code that demonstrates security issues detected by our pipeline.
This file is for educational purposes to show how security tools detect problems.

DO NOT USE THIS CODE IN PRODUCTION!
"""

import os
import sqlite3
from flask import Flask, request
import hashlib

app = Flask(__name__)

# ❌ SECURITY ISSUE: Hard-coded credentials (SonarQube will detect this)
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "my-super-secret-key-12345"
API_TOKEN = "sk-1234567890abcdef1234567890abcdef"


@app.route('/vulnerable-user')
def get_vulnerable_user():
    """
    ❌ SECURITY ISSUE: SQL Injection vulnerability
    SonarQube will detect this as a critical security issue
    """
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # This is vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()

    conn.close()
    return str(result) if result else "User not found"


@app.route('/vulnerable-greeting')
def vulnerable_greeting():
    """
    ❌ SECURITY ISSUE: Cross-Site Scripting (XSS)
    SonarQube will detect this XSS vulnerability
    """
    name = request.args.get('name', 'World')
    # Direct HTML output without escaping - XSS vulnerability
    return f"<h1>Hello {name}!</h1>"


def weak_password_hash(password):
    """
    ❌ SECURITY ISSUE: Weak cryptographic function
    SonarQube will detect MD5 as cryptographically weak
    """
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


@app.route('/insecure-config')
def insecure_config():
    """
    ❌ SECURITY ISSUE: Exposing sensitive configuration
    """
    config = {
        'database_password': DATABASE_PASSWORD,  # Hard-coded secret exposure
        'secret_key': SECRET_KEY,
        'api_token': API_TOKEN
    }
    return config


def vulnerable_file_handling():
    """
    ❌ SECURITY ISSUE: Path traversal vulnerability
    SonarQube will detect this as a security hotspot
    """
    filename = request.args.get('file')
    # No path validation - allows directory traversal
    with open(f"/app/files/{filename}", 'r') as f:
        return f.read()


if __name__ == '__main__':
    # ❌ SECURITY ISSUE: Debug mode in production
    app.run(host='0.0.0.0', port=5000, debug=True)
