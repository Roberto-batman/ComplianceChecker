import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io
from openai import AzureOpenAI

app = func.FunctionApp()


# Add this import at the top of your function_app.py
from datetime import datetime



# Enhanced NIST controls with sub-requirements
NIST_CONTROLS = {
    "AC-1": {
        "title": "Policy and Procedures",
        "definition": "The organization develops, documents, and disseminates an access control policy and procedures.",
        "sub_requirements": {
            "AC-1(A)(a)": "Develops, documents, and disseminates an access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance",
            "AC-1(A)(b)": "Develops, documents, and disseminates procedures to facilitate the implementation of the access control policy and associated controls",
            "AC-1(B)(a)": "Reviews and updates the current access control policy at least every 3 years or when significant changes occur",
            "AC-1(B)(b)": "Reviews and updates the current access control procedures at least every 3 years or when significant changes occur"
        }
    },
    "AC-2": {
        "title": "Account Management", 
        "definition": "The organization manages information system accounts...",
        "sub_requirements": {
            "AC-2(A)": "The organization identifies and selects which types of information system accounts support organizational missions/business functions.",
            "AC-2(B)": "The organization assigns account managers for information system accounts.",
            "AC-2(C)": "The organization establishes conditions for group and role membership.",
            "AC-2(D)": "The organization specifies authorized users of the information system, group and role membership, and access authorizations (i.e., privileges) and other attributes (as required) for each account.",
            "AC-2(E)": "The organization requires approvals by responsible managers for requests to create information system accounts.",
            "AC-2(F)": "The organization creates, enables, modifies, disables, and removes information system accounts in accordance with information system account management procedures.",
            "AC-2(G)": "The organization monitors the use of information system accounts.",
            "AC-2(H)(a)": "The organization notifies account managers when accounts are no longer required",
            "AC-2(H)(b)": "The organization notifies account managers when users are terminated or transferred",
            "AC-2(H)(c)": "The organization notifies account managers when individual information system usage or need-to-know changes",
            "AC-2(I)(a)": "The organization authorizes access to the information system based on a valid access authorization",
            "AC-2(I)(b)": "The organization authorizes access to the information system based on intended system usage",
            "AC-2(I)(c)": "The organization authorizes access to the information system based on other attributes as required by the organization or associated missions/business functions",
            "AC-2(J)": "The organization reviews accounts for compliance with account management requirements at least annually",
            "AC-2(K)": "The organization establishes a process for reissuing shared/group account credentials (if deployed) when individuals are removed from the group"
        }
    },
    "AC-3": {
        "title": "Access Enforcement",
        "definition": "The information system enforces approved authorizations for logical access to information and system resources.",
        "sub_requirements": {
            "AC-3(A)": "Enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies"
        }
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
        

        # Then replace your AI prompt section (around line 60) with this:
        current_date = datetime.now().strftime('%B %d, %Y')

        prompt = f"""
        Today's date is {current_date}. 

        Analyze the following policy document for compliance with NIST control {control_id}: {control_info['title']}.

        Control definition: {control_info['definition']}

        Document text: {text_content[:8000]}  

        Important: For time-based requirements (like "every 3 years" or "annually"), consider today's date when evaluating compliance. For example, if a policy was reviewed in 2023 and it's now 2025, that's within a 3-year requirement.

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