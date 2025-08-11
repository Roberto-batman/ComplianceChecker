import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io

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
        
        # Return debug info about the PDF processing
        debug_info = {
            "message": "PDF processed successfully!",
            "pdf_info": {
                "filename": pdf_file.filename,
                "size_bytes": len(pdf_content),
                "page_count": page_count,
                "text_length": len(text_content),
                "first_100_chars": text_content[:100] + "..." if len(text_content) > 100 else text_content
            },
            "environment_check": {
                "endpoint": os.environ.get('AZURE_OPENAI_ENDPOINT', 'NOT_FOUND'),
                "deployment": os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'NOT_FOUND'),
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
            "debug": "PDF processing failed"
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