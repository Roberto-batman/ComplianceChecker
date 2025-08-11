import azure.functions as func
import logging
import json
import os

app = func.FunctionApp()

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Compliance Checker triggered')
    
    # Simple test response with environment variable check
    debug_info = {
        "message": "Function is working!",
        "environment_check": {
            "endpoint": os.environ.get('AZURE_OPENAI_ENDPOINT', 'NOT_FOUND'),
            "deployment": os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'NOT_FOUND'),
            "api_version": os.environ.get('AZURE_OPENAI_API_VERSION', 'NOT_FOUND'),
            "key_exists": 'YES' if os.environ.get('AZURE_OPENAI_KEY') else 'NO',
            # Also check alternative environment variable names
            "alt_endpoint": os.environ.get('AZURE_ENDPOINT', 'NOT_FOUND'),
            "alt_key_exists": 'YES' if os.environ.get('AZURE_API_KEY') else 'NO',
            "subscription_key_exists": 'YES' if os.environ.get('subscription_key') else 'NO'
        }
    }
    
    return func.HttpResponse(
        json.dumps(debug_info),
        status_code=200,
        mimetype="application/json",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        }
    )