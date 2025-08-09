import azure.functions as func
import json
import logging
import os
from openai import AzureOpenAI
import PyPDF2
import io
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = func.FunctionApp()

# NIST AC Controls - subset for MVP
NIST_CONTROLS = {
    "AC-1": {
        "title": "Access Control Policy and Procedures",
        "definition": "(A) The organization develops, documents, and disseminates to personnel or roles with access control responsibilities: (a) An access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and (b) Procedures to facilitate the implementation of the access control policy and associated access controls."
    },
    "AC-2": {
        "title": "Account Management", 
        "definition": "(A) The organization identifies and selects which types of information system accounts support organizational missions/business functions. (B) The organization assigns account managers for information system accounts. (C) The organization establishes conditions for group and role membership."
    },
    "AC-3": {
        "title": "Access Enforcement",
        "definition": "(A) The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies."
    },
    "AC-5": {
        "title": "Separation of Duties",
        "definition": "(A) The organization: (a) Separate organization-defined duties of individuals including at least separation of operational, development, security monitoring, and management functions; (b) Documents separation of duties of individuals; and (c) Defines information system access authorizations to support separation of duties."
    },
    "AC-6": {
        "title": "Least Privilege",
        "definition": "(A) The organization employs the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) which are necessary to accomplish assigned tasks in accordance with organizational missions and business functions."
    }
}

def extract_text_from_pdf(pdf_content):
    """Extract text from PDF bytes"""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_content))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        logging.error(f"Error extracting PDF text: {e}")
        return None

def check_compliance_with_ai(evidence_text, control_id, control_definition):
    """Use Azure OpenAI to check compliance"""
    logging.info(f"Starting compliance check for {control_id}")
    try:
        client = AzureOpenAI(
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_key=os.getenv("AZURE_OPENAI_KEY"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION")
        )
        
        prompt = f"""
Analyze this policy document against NIST control {control_id}.

Control Requirement: {control_definition}

Policy Text: {evidence_text[:3000]}

Respond with ONLY valid JSON - no markdown, no code blocks, no extra text. Just the JSON:
{{"evidence_found": "quoted text or No relevant evidence found", "compliance_status": "Fully Meets", "reasoning": "brief explanation"}}

Use exactly "Fully Meets", "Partially Meets", or "Does Not Meet" for compliance_status.
"""

        response = client.chat.completions.create(
            model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity compliance auditor."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=500
        )
        
        raw_response = response.choices[0].message.content
        logging.info(f"Raw AI response for {control_id}: {raw_response}")
        
        # Clean the response - remove markdown code blocks if present
        cleaned_response = raw_response.strip()
        if cleaned_response.startswith("```json"):
            cleaned_response = cleaned_response.replace("```json", "").replace("```", "").strip()
        elif cleaned_response.startswith("```"):
            cleaned_response = cleaned_response.replace("```", "").strip()
        
        try:
            result = json.loads(cleaned_response)
            return result
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error for {control_id}: {e}")
            logging.error(f"Cleaned response was: {cleaned_response}")
            return {
                "evidence_found": "AI response parsing error",
                "compliance_status": "Error",
                "reasoning": f"Could not parse AI response: {str(e)}"
            }
        
    except Exception as e:
        logging.error(f"Error in AI compliance check: {e}")
        return {
            "evidence_found": "Error processing",
            "compliance_status": "Error",
            "reasoning": str(e)
        }

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Compliance Checker triggered')
    
    # Handle CORS preflight request
    if req.method == 'OPTIONS':
        return func.HttpResponse(
            "",
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )
    
    try:
        # Get uploaded file
        files = req.files
        if not files or 'document' not in files:
            return func.HttpResponse(
                json.dumps({"error": "No PDF file uploaded. Please upload a file with name 'document'"}),
                status_code=400,
                mimetype="application/json"
            )
        
        pdf_file = files['document']
        pdf_content = pdf_file.read()
        
        # Extract text from PDF
        evidence_text = extract_text_from_pdf(pdf_content)
        if not evidence_text:
            return func.HttpResponse(
                json.dumps({"error": "Could not extract text from PDF"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Check compliance for each control
        results = []
        for control_id, control_info in NIST_CONTROLS.items():
            logging.info(f"Checking compliance for {control_id}")
            
            compliance_result = check_compliance_with_ai(
                evidence_text, 
                control_id, 
                control_info["definition"]
            )
            
            results.append({
                "control_id": control_id,
                "title": control_info["title"],
                "definition": control_info["definition"],
                "evidence_found": compliance_result.get("evidence_found", "Error processing"),
                "compliance_status": compliance_result.get("compliance_status", "Error"),
                "reasoning": compliance_result.get("reasoning", "")
            })
        
        return func.HttpResponse(
            json.dumps({"results": results}),
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )
        
    except Exception as e:
        logging.error(f"Error in ComplianceChecker: {e}")
        return func.HttpResponse(
            json.dumps({"error": f"Internal server error: {str(e)}"}),
            status_code=500,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )