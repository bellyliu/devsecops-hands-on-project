"""
Example vulnerable code that demonstrates security issues detected by our pipeline.
This file is for educational purposes to show how security tools detect problems.

DO NOT USE THIS CODE IN PRODUCTION!
"""

import os
import sqlite3
from flask import Flask, request, escape
import hashlib
from flask_wtf.csrf import CSRFProtect

# FIXED: Enable CSRF protection
app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)


# FIXED: Using environment variables for sensitive information
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")
API_TOKEN = os.getenv("API_TOKEN")


@app.route('/vulnerable-user')
def get_vulnerable_user():
    """
    FIXED: SQL Injection vulnerability prevented with parameterized queries
    Using parameterized queries to safely handle user input
    """
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # This is safe from SQL injection using parameterized queries
    query = "SELECT * FROM users WHERE id = :id"
    cursor.execute(query, {"id": user_id})
    result = cursor.fetchone()

    conn.close()
    return str(result) if result else "User not found"


@app.route('/vulnerable-greeting')
def vulnerable_greeting():
    """
    FIXED: Cross-Site Scripting (XSS) prevented with proper escaping
    User input is now escaped to prevent XSS attacks
    """
    name = request.args.get('name', 'World')
    # Escape user input to prevent XSS vulnerability
    return f"<h1>Hello {escape(name)}!</h1>"


def weak_password_hash(password):
    """
    Fixed: Use sha512 instead of MD5
    """
    # SHA512 is cryptographically strong
    return hashlib.sha512(password.encode()).hexdigest()


@app.route('/insecure-config')
def insecure_config():
    """
    SECURITY ISSUE: Exposing sensitive configuration
    """
    config = {
        'database_password': DATABASE_PASSWORD,  # Hard-coded secret exposure
        'secret_key': SECRET_KEY,
        'api_token': API_TOKEN
    }
    return config


def vulnerable_file_handling():
    """
    FIXED: Path traversal vulnerability prevented with proper validation
    """
    filename = request.args.get('file')
    if not filename:
        return "No file specified"
    
    # Sanitize filename to prevent path traversal
    filename = os.path.basename(filename)
    safe_path = os.path.join("/app/files", filename)
    
    # Ensure the resolved path is within the allowed directory
    if not safe_path.startswith("/app/files/"):
        return "Invalid file path"
    
    try:
        with open(safe_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"


if __name__ == '__main__':
    # Fixed security hostspots by disabling debug mode
    app.run(host='0.0.0.0', port=5000)
