"""
A simple Flask "Hello World" application for DevSecOps pipeline demonstration.
"""

from flask import Flask, jsonify
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)  # Compliant

@app.route('/')
def hello_world():
    """Return a simple hello world message."""
    return jsonify({
        'message': 'Hello, World!',
        'status': 'success',
        'version': '1.0.0'
    })


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'flask-app'
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
