import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io
from openai import AzureOpenAI

app = func.FunctionApp()

# Simplified NIST controls for testing
NIST_CONTROLS = {
    "AC-1": {
        "title": "Policy and Procedures",
        "definition": "The organization develops, documents, and disseminates an access control policy and procedures."
    },
    "AC-2": {
        "title": "Account Management", 
        "definition": "The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts."
    },
    "AC-3": {
        "title": "Access Enforcement",
        "definition": "The information system enforces approved authorizations for logical access to information and system resources."
    }
}

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
        
        for page_num, page in enumerate(reader.pages):
            page_text = page.extract_text()
            text_content += f"\n--- Page {page_num + 1} ---\n{page_text}"
        
        # Initialize Azure OpenAI client
        client = AzureOpenAI(
            api_version=os.environ.get('AZURE_OPENAI_API_VERSION'),
            azure_endpoint=os.environ.get('AZURE_OPENAI_ENDPOINT'),
            api_key=os.environ.get('AZURE_OPENAI_KEY')
        )
        
        results = []
        
        # Process each control
        for control_id, control_info in NIST_CONTROLS.items():
            
            # Create prompt for AI
            prompt = f"""
            Analyze the following policy document for compliance with NIST control {control_id}: {control_info['title']}.
            
            Control definition: {control_info['definition']}
            
            Document text: {text_content[:8000]}  
            
            Provide a JSON response with:
            - "evidence": quoted text from the document that supports this control (or "No evidence found")
            - "status": either "Fully Meets", "Partially Meets", or "Does Not Meet"
            - "confidence": a number between 0 and 1
            
            Response must be valid JSON only.
            """
            
            # Call Azure OpenAI
            ai_response = client.chat.completions.create(
                model=os.environ.get('AZURE_OPENAI_DEPLOYMENT'),
                messages=[
                    {"role": "system", "content": "You are a NIST compliance expert. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.1
            )
            
            response_text = ai_response.choices[0].message.content.strip()
            
            # Clean up the response (remove markdown if present)
            if response_text.startswith('```json'):
                response_text = response_text.replace('```json', '').replace('```', '').strip()
            
            try:
                ai_result = json.loads(response_text)
                
                result = {
                    "control_id": control_id,
                    "title": control_info['title'],
                    "evidence": ai_result.get('evidence', 'No evidence found'),
                    "status": ai_result.get('status', 'Does Not Meet'),
                    "confidence": ai_result.get('confidence', 0.0)
                }
                
            except json.JSONDecodeError:
                result = {
                    "control_id": control_id,
                    "title": control_info['title'],
                    "evidence": "AI response parsing error",
                    "status": "Error",
                    "confidence": 0.0
                }
            
            results.append(result)
        
        return func.HttpResponse(
            json.dumps({"results": results}),
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
            "error_type": type(e).__name__
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