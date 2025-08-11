import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io
from openai import AzureOpenAI

app = func.FunctionApp()

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Compliance Checker triggered')
    
    try:
        # Get uploaded file
        files = req.files
        if not files or 'document' not in files:
            return func.HttpResponse(
                json.dumps({"error": "No PDF file uploaded. Please upload a file with name 'document'"}),
                status_code=400,
                mimetype="application/json",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            )

        pdf_file = files['document']
        pdf_content = pdf_file.read()
        
        # Extract text from PDF
        reader = PdfReader(io.BytesIO(pdf_content))
        text_content = ""
        page_count = len(reader.pages)
        
        for page_num, page in enumerate(reader.pages):
            page_text = page.extract_text()
            text_content += f"\n--- Page {page_num + 1} ---\n{page_text}"
        
        # Test Azure OpenAI connection
        client = AzureOpenAI(
            api_version=os.environ.get('AZURE_OPENAI_API_VERSION'),
            azure_endpoint=os.environ.get('AZURE_OPENAI_ENDPOINT'),
            api_key=os.environ.get('AZURE_OPENAI_KEY')
        )
        
        # Simple test call
        test_response = client.chat.completions.create(
            model=os.environ.get('AZURE_OPENAI_DEPLOYMENT'),
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say 'Hello, Azure OpenAI is working!' in JSON format with a 'message' field."}
            ],
            max_tokens=100,
            temperature=0
        )
        
        ai_response = test_response.choices[0].message.content
        
        # Return debug info including AI test
        debug_info = {
            "message": "PDF and AI both working!",
            "pdf_info": {
                "filename": pdf_file.filename,
                "page_count": page_count,
                "text_length": len(text_content)
            },
            "ai_test": {
                "status": "success",
                "response": ai_response
            },
            "environment_check": {
                "endpoint": os.environ.get('AZURE_OPENAI_ENDPOINT'),
                "deployment": os.environ.get('AZURE_OPENAI_DEPLOYMENT'),
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
        
    except Exception as e:
        error_info = {
            "error": f"Error processing document: {str(e)}",
            "error_type": type(e).__name__,
            "debug": "AI connection test failed"
        }
        logging.error(f"Compliance check failed: {str(e)}")
        return func.HttpResponse(
            json.dumps(error_info),
            status_code=500,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )