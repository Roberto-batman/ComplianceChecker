import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io
from openai import AzureOpenAI
from datetime import datetime

app = func.FunctionApp()

# Enhanced NIST controls with detailed assessment criteria
NIST_CONTROLS = {
    "AC-1": {
        "name": "Access Control Policy and Procedures",
        "title": "Access Control Policy and Procedures",
        "definition": "(A) The organization develops, documents, and disseminates to personnel or roles with access control responsibilities:\n(a) An access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and\n(b) Procedures to facilitate the implementation of the access control policy and associated access controls.\n(B) The organization reviews and updates the current:\n(a) Access control policy at least every 3 years; and\n(b) Access control procedures at least annually.",
        "sub_requirements": {
            "AC-1(A)(a)": {
                "title": "Access control policy development",
                "definition": "Develops, documents, and disseminates an access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance",
                "assessment_criteria": {
                    "purpose": "Look for explicit statement of why the policy exists, its objectives, or what it aims to achieve",
                    "scope": "Look for definition of what systems, users, or situations the policy covers",
                    "roles": "Look for identification of who has what responsibilities (managers, users, administrators, etc.)",
                    "responsibilities": "Look for specific duties assigned to different parties",
                    "management_commitment": "Look for evidence of organizational leadership support, training requirements, or enforcement mechanisms",
                    "coordination": "Look for processes that involve multiple parties working together or communicating",
                    "compliance": "Look for enforcement mechanisms, consequences for violations, or compliance monitoring"
                }
            },
            "AC-1(A)(b)": {
                "title": "Procedures development", 
                "definition": "Develops, documents, and disseminates procedures to facilitate the implementation of the access control policy and associated access controls",
                "assessment_criteria": {
                    "procedures_exist": "Look for step-by-step processes, workflows, or detailed instructions",
                    "implementation_focus": "Look for procedures that explain HOW to implement the policy",
                    "documentation": "Evidence that procedures are written down and maintained",
                    "dissemination": "Evidence that procedures are shared with relevant personnel"
                }
            },
            "AC-1(B)(a)": {
                "title": "Policy review and update",
                "definition": "Reviews and updates the current access control policy at least every 3 years",
                "assessment_criteria": {
                    "review_frequency": "Look for evidence of regular reviews, version history, or update schedules",
                    "three_year_cycle": "Check if reviews happen at least every 3 years based on document dates"
                }
            },
            "AC-1(B)(b)": {
                "title": "Procedures review and update",
                "definition": "Reviews and updates the current access control procedures at least annually",
                "assessment_criteria": {
                    "review_frequency": "Look for evidence of regular reviews, version history, or update schedules",
                    "annual_cycle": "Check if reviews happen at least annually based on document dates"
                }
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
                "definition": "The organization identifies and selects which types of information system accounts support organizational missions/business functions.",
                "assessment_criteria": {
                    "account_types": "Look for mentions of different user categories, account types, or user groups",
                    "business_alignment": "Evidence that account types are tied to business needs or functions"
                }
            },
            "AC-2(B)": {
                "title": "Account manager assignment",
                "definition": "The organization assigns account managers for information system accounts.",
                "assessment_criteria": {
                    "manager_designation": "Look for assignment of specific people to manage accounts",
                    "accountability": "Evidence of who is responsible for account oversight"
                }
            },
            "AC-2(E)": {
                "title": "Account creation approval",
                "definition": "The organization requires approvals by responsible managers for requests to create information system accounts.",
                "assessment_criteria": {
                    "approval_process": "Look for requirement that managers must approve new accounts",
                    "formal_request": "Evidence of formal process for requesting new accounts"
                }
            },
            "AC-2(F)": {
                "title": "Account lifecycle management",
                "definition": "The organization creates, enables, modifies, disables, and removes information system accounts in accordance with information system account management procedures.",
                "assessment_criteria": {
                    "lifecycle_processes": "Look for procedures covering account creation, modification, disabling, removal",
                    "systematic_approach": "Evidence of organized processes for managing account changes"
                }
            },
            "AC-2(J)": {
                "title": "Annual account review",
                "definition": "The organization reviews accounts for compliance with account management requirements at least annually.",
                "assessment_criteria": {
                    "regular_review": "Look for evidence of periodic account reviews",
                    "annual_frequency": "Reviews happening at least once per year"
                }
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
                "definition": "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
                "assessment_criteria": {
                    "enforcement_mechanisms": "Look for technical controls that prevent unauthorized access",
                    "authorization_requirement": "Evidence that access is granted only after proper authorization",
                    "policy_compliance": "Access controls that align with stated policies"
                }
            }
        }
    }
}

def create_enhanced_prompt(sub_id, sub_info, control_info, document_text, current_date):
    """Create a detailed, criteria-based assessment prompt"""
    
    # Get assessment criteria if available
    criteria = sub_info.get('assessment_criteria', {})
    
    base_prompt = f"""
Today's date is {current_date}.

You are analyzing compliance with NIST sub-requirement {sub_id}: {sub_info['title']}.

Sub-requirement definition: {sub_info['definition']}

Parent control {sub_id.split('(')[0]}: {control_info['title']}

CRITICAL ASSESSMENT INSTRUCTIONS:
1. SYSTEMATIC EVIDENCE SEARCH: Look systematically through the document for ALL components
2. POSITIVE EVIDENCE BIAS: If evidence exists for the requirement, lean toward "Fully Meets" unless clearly incomplete
3. COMPONENT BREAKDOWN: For complex requirements with multiple parts, check each component individually
4. DIRECT QUOTES REQUIRED: Always provide specific quoted text from the document as evidence

"""

    if criteria:
        base_prompt += f"""
SPECIFIC CRITERIA TO CHECK for {sub_id}:
"""
        for criterion, description in criteria.items():
            base_prompt += f"• {criterion.upper()}: {description}\n"
        
        base_prompt += """
ASSESSMENT LOGIC:
- If 80-100% of criteria have evidence → "Fully Meets" 
- If 50-79% of criteria have evidence → "Partially Meets"
- If less than 50% of criteria have evidence → "Does Not Meet"

"""

    base_prompt += f"""
DOCUMENT TEXT TO ANALYZE:
{document_text[:8000]}

REQUIRED JSON RESPONSE FORMAT:
{{
    "evidence": "Direct quotes from document that support this requirement (be thorough and specific)",
    "status": "Fully Meets" | "Partially Meets" | "Does Not Meet",
    "confidence": 0.0-1.0,
    "criteria_analysis": {{
        "components_found": ["list of requirement components found in document"],
        "missing_components": ["list of requirement components not found"]
    }}
}}

IMPORTANT: Be thorough in finding evidence. If the document contains the required elements, assess as "Fully Meets" even if the wording isn't perfect.
"""
    
    return base_prompt

def calculate_overall_control_status(sub_results):
    """Calculate overall control status with enhanced logic"""
    if not sub_results:
        return "Does Not Meet"
    
    valid_results = [r for r in sub_results if r['status'] not in ['Error']]
    if not valid_results:
        return "Does Not Meet"
    
    total = len(valid_results)
    fully_meets = sum(1 for r in valid_results if r['status'] == 'Fully Meets')
    partially_meets = sum(1 for r in valid_results if r['status'] == 'Partially Meets') 
    does_not_meet = sum(1 for r in valid_results if r['status'] == 'Does Not Meet')
    
    # Enhanced assessment logic
    if does_not_meet == 0 and fully_meets >= total * 0.8:  # 80% fully meet
        return "Fully Meets"
    elif does_not_meet > total * 0.5:  # Majority don't meet
        return "Does Not Meet"
    else:
        return "Partially Meets"

def calculate_overall_confidence(sub_results):
    """Calculate weighted average confidence"""
    valid_results = [r for r in sub_results if r['status'] not in ['Error']]
    if not valid_results:
        return 0.0
    
    # Weight confidence by status (fully meets = higher weight)
    weighted_sum = 0
    total_weight = 0
    
    for r in valid_results:
        weight = 1.0
        if r['status'] == 'Fully Meets':
            weight = 1.2
        elif r['status'] == 'Does Not Meet':
            weight = 0.8
            
        weighted_sum += r['confidence'] * weight
        total_weight += weight
    
    return weighted_sum / total_weight

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Enhanced Compliance Checker triggered')
    
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
            
            # Process sub-requirements
            if control_info['sub_requirements']:
                sub_results = []
                
                for sub_id, sub_info in control_info['sub_requirements'].items():
                    logging.info(f"  Analyzing sub-requirement {sub_id}")
                    
                    try:
                        # Create enhanced prompt
                        prompt = create_enhanced_prompt(sub_id, sub_info, control_info, text_content, current_date)
                        
                        # Call Azure OpenAI for sub-requirement
                        ai_response = client.chat.completions.create(
                            model=os.environ.get('AZURE_OPENAI_DEPLOYMENT'),
                            messages=[
                                {"role": "system", "content": "You are a thorough NIST compliance expert. Look systematically for evidence and be generous in finding compliance when evidence exists. Respond only with valid JSON."},
                                {"role": "user", "content": prompt}
                            ],
                            max_tokens=1200,
                            temperature=0.1
                        )
                        
                        response_text = ai_response.choices[0].message.content.strip()
                        logging.info(f"AI response for {sub_id}: {response_text[:200]}...")
                        
                        # Clean up response
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
                                "confidence": ai_result.get('confidence', 0.0),
                                "criteria_analysis": ai_result.get('criteria_analysis', {})
                            }
                            
                            sub_results.append(sub_result)
                            
                        except json.JSONDecodeError as json_err:
                            logging.error(f"JSON parse error for {sub_id}: {str(json_err)}")
                            logging.error(f"Raw response: {response_text}")
                            sub_result = {
                                "sub_id": sub_id,
                                "title": sub_info['title'],
                                "definition": sub_info['definition'],
                                "evidence": "AI response parsing error",
                                "status": "Error",
                                "confidence": 0.0,
                                "criteria_analysis": {}
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
                            "confidence": 0.0,
                            "criteria_analysis": {}
                        }
                        sub_results.append(sub_result)
                
                # Calculate overall control status
                control_result["overall_status"] = calculate_overall_control_status(sub_results)
                control_result["overall_confidence"] = calculate_overall_confidence(sub_results)
                
                # Combine evidence from successful sub-requirements
                evidence_pieces = [r['evidence'] for r in sub_results if r['evidence'] != 'No evidence found' and r['status'] != 'Error']
                if evidence_pieces:
                    control_result["overall_evidence"] = " | ".join(evidence_pieces[:2])  # Top 2 pieces
                
                control_result["sub_requirements"] = sub_results
            
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