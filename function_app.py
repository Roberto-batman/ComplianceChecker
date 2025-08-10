@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Compliance Checker triggered')
    
    import os
    
    # Simple test response with environment variable check
    debug_info = {
        "message": "Function is working!",
        "environment_check": {
            "endpoint": os.environ.get('AZURE_OPENAI_ENDPOINT', 'NOT_FOUND'),
            "deployment": os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'NOT_FOUND'),
            "api_version": os.environ.get('AZURE_OPENAI_API_VERSION', 'NOT_FOUND'),
            "key_exists": 'YES' if os.environ.get('AZURE_OPENAI_KEY') else 'NO'
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