import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io
from openai import AzureOpenAI
from datetime import datetime

app = func.FunctionApp()

# Complete NIST controls with sub-requirements from Excel file
NIST_CONTROLS = {
    "AC-1": {
        "name": "Access Control Policy and Procedures",
        "title": "Access Control Policy and Procedures",
        "definition": "(A) The organization develops, documents, and disseminates to personnel or roles with access control responsibilities:\n(a) An access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and\n(b) Procedures to facilitate the implementation of the access control policy and associated access controls.\n(B) The organization reviews and updates the current:\n(a) Access control policy at least every 3 years; and\n(b) Access control procedures at least annually.",
        "sub_requirements": {
            "AC-1(A)(a)": {
                "title": "Access control policy development",
                "definition": "Develops, documents, and disseminates an access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance"
            },
            "AC-1(A)(b)": {
                "title": "Procedures development", 
                "definition": "Develops, documents, and disseminates procedures to facilitate the implementation of the access control policy and associated access controls"
            },
            "AC-1(B)(a)": {
                "title": "Policy review and update",
                "definition": "Reviews and updates the current access control policy at least every 3 years"
            },
            "AC-1(B)(b)": {
                "title": "Procedures review and update",
                "definition": "Reviews and updates the current access control procedures at least annually"
            }
        }
    },
    "AC-2": {
        "name": "Account Management",
        "title": "Account Management",
        "definition": "(A) The organization identifies and selects which types of information system accounts support organizational missions/business functions.\n(B) The organization assigns account managers for information system accounts.\n(C) The organization establishes conditions for group and role membership.\n(D) The organization specifies authorized users of the information system, group and role membership, and access authorizations (i.e., privileges) and other attributes (as required) for each account.\n(E) The organization requires approvals by responsible managers for requests to create information system accounts.\n(F) The organization creates, enables, modifies, disables, and removes information system accounts in accordance with information system account management procedures.\n(G) The organization monitors the use of information system accounts.\n(H) The organization notifies account managers:\n(a) When accounts are no longer required;\n(b) When users are terminated or transferred; and\n(c) When individual information system usage or need-to-know changes.\n(I) The organization authorizes access to the information system based on:\n(a) A valid access authorization;\n(b) Intended system usage; and\n(c) Other attributes as required by the organization or associated missions/business functions.\n(J) The organization reviews accounts for compliance with account management requirements at least annually.\n(K) The organization establishes a process for reissuing shared/group account credentials (if deployed) when individuals are removed from the group.",
        "sub_requirements": {
            "AC-2(A)": {
                "title": "Account type identification",
                "definition": "The organization identifies and selects which types of information system accounts support organizational missions/business functions."
            },
            "AC-2(B)": {
                "title": "Account manager assignment",
                "definition": "The organization assigns account managers for information system accounts."
            },
            "AC-2(C)": {
                "title": "Group and role membership conditions",
                "definition": "The organization establishes conditions for group and role membership."
            },
            "AC-2(D)": {
                "title": "Account specifications",
                "definition": "The organization specifies authorized users of the information system, group and role membership, and access authorizations (i.e., privileges) and other attributes (as required) for each account."
            },
            "AC-2(E)": {
                "title": "Account creation approval",
                "definition": "The organization requires approvals by responsible managers for requests to create information system accounts."
            },
            "AC-2(F)": {
                "title": "Account lifecycle management",
                "definition": "The organization creates, enables, modifies, disables, and removes information system accounts in accordance with information system account management procedures."
            },
            "AC-2(G)": {
                "title": "Account monitoring",
                "definition": "The organization monitors the use of information system accounts."
            },
            "AC-2(H)(a)": {
                "title": "Notification - accounts no longer required",
                "definition": "The organization notifies account managers when accounts are no longer required."
            },
            "AC-2(H)(b)": {
                "title": "Notification - user termination/transfer",
                "definition": "The organization notifies account managers when users are terminated or transferred."
            },
            "AC-2(H)(c)": {
                "title": "Notification - usage/need-to-know changes",
                "definition": "The organization notifies account managers when individual information system usage or need-to-know changes."
            },
            "AC-2(I)(a)": {
                "title": "Authorization - valid access",
                "definition": "The organization authorizes access to the information system based on a valid access authorization."
            },
            "AC-2(I)(b)": {
                "title": "Authorization - intended usage",
                "definition": "The organization authorizes access to the information system based on intended system usage."
            },
            "AC-2(I)(c)": {
                "title": "Authorization - other attributes",
                "definition": "The organization authorizes access to the information system based on other attributes as required by the organization or associated missions/business functions."
            },
            "AC-2(J)": {
                "title": "Annual account review",
                "definition": "The organization reviews accounts for compliance with account management requirements at least annually."
            },
            "AC-2(K)": {
                "title": "Shared account credential reissuance",
                "definition": "The organization establishes a process for reissuing shared/group account credentials (if deployed) when individuals are removed from the group."
            }
        }
    },
    "AC-3": {
        "name": "Access Enforcement",
        "title": "Access Enforcement",
        "definition": "(A) The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        "sub_requirements": {
            "AC-3(A)": {
                "title": "Logical access enforcement",
                "definition": "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies."
            }
        }
    }
}

def calculate_overall_control_status(sub_results):
    """
    Calculate overall control status based on sub-requirement results
    Rules:
    - If any sub-requirement "Does Not Meet" → overall max "Partially Meets"
    - If majority "Does Not Meet" → overall "Does Not Meet"
    - If majority "Fully Meets" and no "Does Not Meet" → overall "Fully Meets"
    - If majority "Partially Meets" → overall "Partially Meets"
    """
    if not sub_results:
        return "Does Not Meet"
    
    total = len(sub_results)
    fully_meets = sum(1 for r in sub_results if r['status'] == 'Fully Meets')
    partially_meets = sum(1 for r in sub_results if r['status'] == 'Partially Meets')
    does_not_meet = sum(1 for r in sub_results if r['status'] == 'Does Not Meet')
    
    # If any sub-requirement doesn't meet, overall can't be "Fully Meets"
    if does_not_meet > 0:
        # If majority doesn't meet, overall doesn't meet
        if does_not_meet > total / 2:
            return "Does Not Meet"
        else:
            return "Partially Meets"
    
    # No sub-requirements fail
    if fully_meets > total / 2:
        return "Fully Meets"
    else:
        return "Partially Meets"

def calculate_overall_confidence(sub_results):
    """Calculate average confidence from sub-requirements"""
    if not sub_results:
        return 0.0
    return sum(r['confidence'] for r in sub_results) / len(sub_results)

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Hierarchical Compliance Checker triggered')
    
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
        
        logging.info(f"Extracted {len(text_content)} characters from PDF")
        
        # Initialize Azure OpenAI client
        client = AzureOpenAI(
            api_version=os.environ.get('AZURE_OPENAI_API_VERSION'),
            azure_endpoint=os.environ.get('AZURE_OPENAI_ENDPOINT'),
            api_key=os.environ.get('AZURE_OPENAI_KEY')
        )
        
        results = []
        current_date = datetime.now().strftime('%B %d, %Y')
        
        # Process each NIST control
        for control_id, control_info in NIST_CONTROLS.items():
            logging.info(f"Analyzing control {control_id}")
            
            control_result = {
                "control_id": control_id,
                "title": control_info['title'],
                "definition": control_info['definition'],
                "sub_requirements": [],
                "overall_status": "Does Not Meet",
                "overall_confidence": 0.0,
                "overall_evidence": "No evidence found"
            }
            
            # If control has sub-requirements, analyze each one
            if control_info['sub_requirements']:
                sub_results = []
                
                for sub_id, sub_info in control_info['sub_requirements'].items():
                    logging.info(f"  Analyzing sub-requirement {sub_id}")
                    
                    try:
                        prompt = f"""
                        Today's date is {current_date}. 

                        Analyze the following policy document for compliance with NIST sub-requirement {sub_id}: {sub_info['title']}.

                        Sub-requirement definition: {sub_info['definition']}

                        Parent control {control_id}: {control_info['title']}
                        Parent definition: {control_info['definition'][:500]}...

                        Document text: {text_content[:7000]}

                        Important: For time-based requirements (like "every 3 years" or "annually"), consider today's date when evaluating compliance.

                        Provide a JSON response with:
                        - "evidence": quoted text from the document that supports this sub-requirement (or "No evidence found")
                        - "status": either "Fully Meets", "Partially Meets", or "Does Not Meet"
                        - "confidence": a number between 0 and 1

                        Response must be valid JSON only.
                        """
                        
                        # Call Azure OpenAI for sub-requirement
                        ai_response = client.chat.completions.create(
                            model=os.environ.get('AZURE_OPENAI_DEPLOYMENT'),
                            messages=[
                                {"role": "system", "content": "You are a NIST compliance expert. Respond only with valid JSON."},
                                {"role": "user", "content": prompt}
                            ],
                            max_tokens=800,
                            temperature=0.1
                        )
                        
                        response_text = ai_response.choices[0].message.content.strip()
                        
                        # Clean up the response
                        if response_text.startswith('```json'):
                            response_text = response_text.replace('```json', '').replace('```', '').strip()
                        
                        try:
                            ai_result = json.loads(response_text)
                            
                            sub_result = {
                                "sub_id": sub_id,
                                "title": sub_info['title'],
                                "definition": sub_info['definition'],
                                "evidence": ai_result.get('evidence', 'No evidence found'),
                                "status": ai_result.get('status', 'Does Not Meet'),
                                "confidence": ai_result.get('confidence', 0.0)
                            }
                            
                            sub_results.append(sub_result)
                            
                        except json.JSONDecodeError as json_err:
                            logging.error(f"JSON parse error for {sub_id}: {str(json_err)}")
                            sub_result = {
                                "sub_id": sub_id,
                                "title": sub_info['title'],
                                "definition": sub_info['definition'],
                                "evidence": "AI response parsing error",
                                "status": "Error",
                                "confidence": 0.0
                            }
                            sub_results.append(sub_result)
                        
                    except Exception as sub_error:
                        logging.error(f"Error processing sub-requirement {sub_id}: {str(sub_error)}")
                        sub_result = {
                            "sub_id": sub_id,
                            "title": sub_info['title'],
                            "definition": sub_info['definition'],
                            "evidence": f"Processing error: {str(sub_error)}",
                            "status": "Error",
                            "confidence": 0.0
                        }
                        sub_results.append(sub_result)
                
                # Calculate overall control status from sub-requirements
                valid_sub_results = [r for r in sub_results if r['status'] != 'Error']
                if valid_sub_results:
                    control_result["overall_status"] = calculate_overall_control_status(valid_sub_results)
                    control_result["overall_confidence"] = calculate_overall_confidence(valid_sub_results)
                    
                    # Combine evidence from sub-requirements
                    evidence_pieces = [r['evidence'] for r in valid_sub_results if r['evidence'] != 'No evidence found']
                    if evidence_pieces:
                        control_result["overall_evidence"] = "; ".join(evidence_pieces[:3])  # Top 3 pieces of evidence
                
                control_result["sub_requirements"] = sub_results
                
            else:
                # Control has no sub-requirements, analyze directly
                try:
                    prompt = f"""
                    Today's date is {current_date}. 

                    Analyze the following policy document for compliance with NIST control {control_id}: {control_info['title']}.

                    Control definition: {control_info['definition']}

                    Document text: {text_content[:8000]}

                    Important: For time-based requirements (like "every 3 years" or "annually"), consider today's date when evaluating compliance.

                    Provide a JSON response with:
                    - "evidence": quoted text from the document that supports this control (or "No evidence found")
                    - "status": either "Fully Meets", "Partially Meets", or "Does Not Meet"
                    - "confidence": a number between 0 and 1

                    Response must be valid JSON only.
                    """
                    
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
                    
                    if response_text.startswith('```json'):
                        response_text = response_text.replace('```json', '').replace('```', '').strip()
                    
                    try:
                        ai_result = json.loads(response_text)
                        
                        control_result["overall_status"] = ai_result.get('status', 'Does Not Meet')
                        control_result["overall_confidence"] = ai_result.get('confidence', 0.0)
                        control_result["overall_evidence"] = ai_result.get('evidence', 'No evidence found')
                        
                    except json.JSONDecodeError as json_err:
                        logging.error(f"JSON parse error for {control_id}: {str(json_err)}")
                        control_result["overall_status"] = "Error"
                        control_result["overall_evidence"] = "AI response parsing error"
                        
                except Exception as control_error:
                    logging.error(f"Error processing control {control_id}: {str(control_error)}")
                    control_result["overall_status"] = "Error"
                    control_result["overall_evidence"] = f"Processing error: {str(control_error)}"
            
            results.append(control_result)
        
        return func.HttpResponse(
            json.dumps({"results": results}, indent=2),
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