#!/usr/bin/env python3
"""
Root endpoint for SeleniumBase API
"""
from flask import jsonify


def register_routes(app):
    """Register root routes with the Flask app"""
    
    @app.route('/', methods=['GET'])
    def index():
        """Root endpoint with API documentation"""
        return jsonify({
            'service': 'SeleniumBase API',
            'version': '1.0.0',
            'endpoints': {
                '/api/article': {
                    'method': 'GET or POST',
                    'description': 'Fetch HTML content from a URL',
                    'parameters': {
                        'url': 'The URL to fetch (required)',
                        'cookies': 'POST-only structured browser cookies',
                        'return-cookies': 'POST/GET boolean; return the browser cookie snapshot',
                        'extra-http-headers': 'POST JSON object (or legacy string in the body)',
                        'http-credentials': 'POST JSON object (or legacy string in the body)'
                    },
                    'example': '/api/article?url=https://example.com'
                },
                '/health': {
                    'method': 'GET',
                    'description': 'Health check endpoint'
                }
            }
        }), 200
