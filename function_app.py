import azure.functions as func
import logging
import json
import os
from PyPDF2 import PdfReader
import io
from openai import AzureOpenAI
from datetime import datetime, timezone

app = func.FunctionApp()

def determine_evidence_requirements(control_definition):
    """
    Analyze control definition to determine evidence requirements based on linguistic patterns.
    
    Pattern Recognition Rules:
    1. "The organization..." = Organizational control - can be fully met through policy/procedures
    2. "The information system..." = Technical control - requires system implementation evidence
    3. Other patterns = Mixed/unclear - requires careful analysis
    """
    control_definition = control_definition.strip()
    
    if control_definition.startswith("The information system"):
        return {
            "type": "technical_implementation",
            "policy_max_score": "Partially Meets",
            "full_compliance_requires": ["system_evidence", "technical_proof", "implementation_verification"],
            "reasoning": "Technical control requires system implementation evidence - policy alone insufficient",
            "evidence_examples": "system configurations, screenshots, logs, audit reports, technical testing results"
        }
    elif control_definition.startswith("The organization"):
        return {
            "type": "organizational",
            "policy_max_score": "Fully Meets",
            "full_compliance_requires": ["policy", "procedures", "organizational_processes"],
            "reasoning": "Organizational control can be met through documented policies and procedures",
            "evidence_examples": "policy documents, procedures, organizational charts, training records"
        }
    else:
        return {
            "type": "mixed_or_unclear",
            "policy_max_score": "Partially Meets",
            "full_compliance_requires": ["contextual_analysis_needed"],
            "reasoning": "Control type unclear from definition - requires careful evidence analysis",
            "assessment_note": "Analyze specific control requirements to determine appropriate evidence types"
        }

# Enhanced NIST controls with pattern-based assessment
NIST_CONTROLS = {
    "AC-1": {
        "name": "Access Control Policy and Procedures",
        "title": "Access Control Policy and Procedures",
        "definition": "(A) The organization develops, documents, and disseminates to personnel or roles with access control responsibilities:\n(a) An access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and\n(b) Procedures to facilitate the implementation of the access control policy and associated access controls.\n(B) The organization reviews and updates the current:\n(a) Access control policy at least every 3 years; and\n(b) Access control procedures at least annually.",
        "sub_requirements": {
            "AC-1(A)(a)": {
                "title": "Access control policy development",
                "definition": "The organization develops, documents, and disseminates an access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance",
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
                "definition": "The organization develops, documents, and disseminates procedures to facilitate the implementation of the access control policy and associated access controls",
                "assessment_criteria": {
                    "procedures_exist": "Look for step-by-step processes, workflows, or detailed instructions",
                    "implementation_focus": "Look for procedures that explain HOW to implement the policy",
                    "documentation": "Evidence that procedures are written down and maintained",
                    "dissemination": "Evidence that procedures are shared with relevant personnel"
                }
            },
            "AC-1(B)(a)": {
                "title": "Policy review and update",
                "definition": "The organization reviews and updates the current access control policy at least every 3 years",
                "assessment_criteria": {
                    "review_frequency": "Look for evidence of regular reviews, version history, or update schedules",
                    "three_year_cycle": "Check if reviews happen at least every 3 years based on document dates"
                }
            },
            "AC-1(B)(b)": {
                "title": "Procedures review and update",
                "definition": "The organization reviews and updates the current access control procedures at least annually",
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
            "AC-2(C)": {
                "title": "Group and role membership conditions",
                "definition": "The organization establishes conditions for group and role membership.",
                "assessment_criteria": {
                    "membership_criteria": "Look for rules about who can belong to groups or roles",
                    "access_conditions": "Evidence of requirements for group/role assignment"
                }
            },
            "AC-2(D)": {
                "title": "Account specifications",
                "definition": "The organization specifies authorized users of the information system, group and role membership, and access authorizations (i.e., privileges) and other attributes (as required) for each account.",
                "assessment_criteria": {
                    "user_specification": "Look for identification of authorized users",
                    "privilege_definition": "Evidence of defined access levels and permissions",
                    "attribute_management": "Documentation of account attributes and characteristics"
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
            "AC-2(G)": {
                "title": "Account monitoring",
                "definition": "The organization monitors the use of information system accounts.",
                "assessment_criteria": {
                    "monitoring_processes": "Look for evidence of account usage monitoring",
                    "oversight_mechanisms": "Procedures for tracking account activity"
                }
            },
            "AC-2(H)(a)": {
                "title": "Notification - accounts no longer required",
                "definition": "The organization notifies account managers when accounts are no longer required.",
                "assessment_criteria": {
                    "notification_process": "Look for procedures to notify managers about unneeded accounts",
                    "account_cleanup": "Evidence of processes to identify and remove unused accounts"
                }
            },
            "AC-2(H)(b)": {
                "title": "Notification - user termination/transfer",
                "definition": "The organization notifies account managers when users are terminated or transferred.",
                "assessment_criteria": {
                    "termination_notification": "Look for procedures to notify when users leave",
                    "transfer_notification": "Evidence of notification when users change roles"
                }
            },
            "AC-2(H)(c)": {
                "title": "Notification - usage/need-to-know changes",
                "definition": "The organization notifies account managers when individual information system usage or need-to-know changes.",
                "assessment_criteria": {
                    "usage_change_notification": "Look for procedures to notify about changing access needs",
                    "need_to_know_updates": "Evidence of communication about access requirement changes"
                }
            },
            "AC-2(I)(a)": {
                "title": "Authorization - valid access",
                "definition": "The organization authorizes access to the information system based on a valid access authorization.",
                "assessment_criteria": {
                    "authorization_requirement": "Look for requirement of valid authorization before access",
                    "approval_documentation": "Evidence of formal authorization processes"
                }
            },
            "AC-2(I)(b)": {
                "title": "Authorization - intended usage",
                "definition": "The organization authorizes access to the information system based on intended system usage.",
                "assessment_criteria": {
                    "usage_based_access": "Look for access tied to intended use of systems",
                    "purpose_alignment": "Evidence that access matches job requirements"
                }
            },
            "AC-2(I)(c)": {
                "title": "Authorization - other attributes",
                "definition": "The organization authorizes access to the information system based on other attributes as required by the organization or associated missions/business functions.",
                "assessment_criteria": {
                    "attribute_based_access": "Look for access based on other organizational attributes",
                    "business_function_alignment": "Evidence of access tied to business needs"
                }
            },
            "AC-2(J)": {
                "title": "Annual account review",
                "definition": "The organization reviews accounts for compliance with account management requirements at least annually.",
                "assessment_criteria": {
                    "regular_review": "Look for evidence of periodic account reviews",
                    "annual_frequency": "Reviews happening at least once per year"
                }
            },
            "AC-2(K)": {
                "title": "Shared account credential reissuance",
                "definition": "The organization establishes a process for reissuing shared/group account credentials (if deployed) when individuals are removed from the group.",
                "assessment_criteria": {
                    "credential_reissuance": "Look for procedures to change shared credentials when users leave",
                    "shared_account_management": "Evidence of processes for managing group accounts"
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
                    "technical_enforcement": "Look for evidence of automated/technical controls that prevent unauthorized access",
                    "system_implementation": "Evidence of actual system configurations, not just policy statements",
                    "authorization_verification": "Proof that systems check authorizations before granting access",
                    "policy_alignment": "Evidence that technical controls match stated policies"
                }
            }
        }
    }
}

def create_pattern_based_prompt(sub_id, sub_info, control_info, document_text, current_date):
    """Create assessment prompt incorporating pattern-based evidence requirements"""
    
    # Determine evidence requirements based on control definition
    evidence_req = determine_evidence_requirements(sub_info['definition'])
    
    base_prompt = f"""
Today's date is {current_date}.

COMPLIANCE ASSESSMENT for {sub_id}: {sub_info['title']}

Sub-requirement definition: {sub_info['definition']}

PATTERN-BASED ASSESSMENT RULES:
Control Type: {evidence_req['type']}
Reasoning: {evidence_req['reasoning']}
Policy Document Maximum Score: {evidence_req['policy_max_score']}
Required Evidence Types: {', '.join(evidence_req['full_compliance_requires'])}
Evidence Examples: {evidence_req.get('evidence_examples', 'Various forms of supporting documentation')}

"""

    # Add assessment note if present
    if 'assessment_note' in evidence_req:
        base_prompt += f"Special Note: {evidence_req['assessment_note']}\n\n"

    # Get assessment criteria if available
    criteria = sub_info.get('assessment_criteria', {})
    
    if criteria:
        base_prompt += f"SPECIFIC CRITERIA TO CHECK:\n"
        for criterion, description in criteria.items():
            base_prompt += f"• {criterion.upper()}: {description}\n"
        base_prompt += "\n"

    base_prompt += f"""
ASSESSMENT INSTRUCTIONS:
1. Analyze the document systematically for evidence related to this requirement
2. Consider the control type when determining compliance level
3. For technical controls: Policy alone = maximum "Partially Meets"
4. For organizational controls: Policy/procedures can achieve "Fully Meets"
5. Quote specific evidence from the document

DOCUMENT TO ANALYZE:
{document_text[:8000]}

REQUIRED JSON RESPONSE:
{{
    "evidence": "Direct quotes from document with page references",
    "status": "Fully Meets" | "Partially Meets" | "Does Not Meet", 
    "confidence": 0.0-1.0,
    "assessment_reasoning": "Explanation of why this score was assigned based on control type and evidence found",
    "evidence_type_analysis": "What types of evidence were found (policy, technical, procedural, etc.)"
}}

Remember: Apply pattern-based rules consistently. Technical implementation controls require more than policy evidence for full compliance.
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

# Warmup endpoint to prevent cold starts
@app.route(route="warmup", auth_level=func.AuthLevel.ANONYMOUS, methods=["GET"])
def warmup(req: func.HttpRequest) -> func.HttpResponse:
    """Simple warmup endpoint to keep function active"""
    logging.info('Warmup endpoint called - function staying active')
    
    # Test basic connectivity
    try:
        # Test environment variables
        endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
        api_key = os.environ.get('AZURE_OPENAI_KEY')
        deployment = os.environ.get('AZURE_OPENAI_DEPLOYMENT')
        
        warmup_response = {
            "status": "warm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment_check": {
                "endpoint_configured": bool(endpoint),
                "api_key_configured": bool(api_key),
                "deployment_configured": bool(deployment)
            }
        }
        
        return func.HttpResponse(
            json.dumps(warmup_response),
            status_code=200,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )
    except Exception as e:
        logging.error(f"Warmup failed: {str(e)}")
        return func.HttpResponse(
            json.dumps({"status": "warmup_failed", "error": str(e)}),
            status_code=500,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    """Enhanced NIST compliance checker with pattern-based assessment"""
    
    # Startup logging for diagnostics
    logging.info('=== NIST Compliance Checker Starting ===')
    logging.info(f'Function invocation ID: {req.url}')
    logging.info('Checking environment variables...')
    
    endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
    api_key = os.environ.get('AZURE_OPENAI_KEY')
    deployment = os.environ.get('AZURE_OPENAI_DEPLOYMENT')
    api_version = os.environ.get('AZURE_OPENAI_API_VERSION')
    
    logging.info(f'Endpoint configured: {bool(endpoint)}')
    logging.info(f'API key configured: {bool(api_key)}')
    logging.info(f'Deployment configured: {bool(deployment)}')
    logging.info(f'API version configured: {bool(api_version)}')
    
    if not all([endpoint, api_key, deployment]):
        logging.error('Missing required environment variables')
        return func.HttpResponse(
            json.dumps({"error": "Azure OpenAI configuration incomplete"}),
            status_code=500,
            mimetype="application/json",
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
                mimetype="application/json",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            )

        pdf_file = files['document']
        pdf_content = pdf_file.read()
        
        logging.info(f'Processing PDF file: {pdf_file.filename} ({len(pdf_content)} bytes)')
        
        # Extract text from PDF
        reader = PdfReader(io.BytesIO(pdf_content))
        text_content = ""
        
        for page_num, page in enumerate(reader.pages):
            page_text = page.extract_text()
            text_content += f"\n--- Page {page_num + 1} ---\n{page_text}"
        
        logging.info(f"Extracted {len(text_content)} characters from {len(reader.pages)} pages")
        
        # Initialize Azure OpenAI client
        logging.info('Initializing Azure OpenAI client...')
        client = AzureOpenAI(
            api_version=api_version,
            azure_endpoint=endpoint,
            api_key=api_key
        )
        logging.info('Azure OpenAI client initialized successfully')
        
        results = []
        current_date = datetime.now().strftime('%B %d, %Y')
        
        # Process each NIST control
        for control_id, control_info in NIST_CONTROLS.items():
            logging.info(f"=== Analyzing control {control_id}: {control_info['title']} ===")
            
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
                    logging.info(f"  → Analyzing sub-requirement {sub_id}")
                    
                    try:
                        # Create pattern-based prompt
                        prompt = create_pattern_based_prompt(sub_id, sub_info, control_info, text_content, current_date)
                        
                        logging.info(f"  → Calling Azure OpenAI for {sub_id}")
                        
                        # Call Azure OpenAI for sub-requirement
                        ai_response = client.chat.completions.create(
                            model=deployment,
                            messages=[
                                {"role": "system", "content": "You are a NIST compliance expert who applies pattern-based assessment rules consistently. Always consider control type when determining maximum possible compliance level."},
                                {"role": "user", "content": prompt}
                            ],
                            max_tokens=1500,
                            temperature=0.1
                        )
                        
                        response_text = ai_response.choices[0].message.content.strip()
                        logging.info(f"  → AI response received for {sub_id} ({len(response_text)} chars)")
                        
                        # Clean up response
                        if response_text.startswith('```json'):
                            response_text = response_text.replace('```json', '').replace('```', '').strip()
                        
                        try:
                            # Additional cleanup for common JSON issues
                            response_text = response_text.strip()
                            if response_text.startswith('"') and response_text.endswith('"'):
                                response_text = response_text[1:-1]  # Remove outer quotes
                            
                            ai_result = json.loads(response_text)
                            
                            # Validate required fields
                            evidence = ai_result.get('evidence', 'No evidence found')
                            status = ai_result.get('status', 'Does Not Meet')
                            confidence = ai_result.get('confidence', 0.0)
                            
                            # Ensure confidence is a number
                            if not isinstance(confidence, (int, float)):
                                confidence = 0.0
                            
                            # Validate status values
                            valid_statuses = ['Fully Meets', 'Partially Meets', 'Does Not Meet']
                            if status not in valid_statuses:
                                status = 'Does Not Meet'
                            
                            sub_result = {
                                "sub_id": sub_id,
                                "title": sub_info['title'],
                                "definition": sub_info['definition'],
                                "evidence": str(evidence),
                                "status": status,
                                "confidence": float(confidence),
                                "assessment_reasoning": ai_result.get('assessment_reasoning', 'No reasoning provided'),
                                "evidence_type_analysis": ai_result.get('evidence_type_analysis', 'No analysis provided')
                            }
                            
                            sub_results.append(sub_result)
                            logging.info(f"  → {sub_id} assessed as: {status} (confidence: {confidence})")
                            
                        except json.JSONDecodeError as json_err:
                            logging.error(f"  → JSON parse error for {sub_id}: {str(json_err)}")
                            logging.error(f"  → Raw response: {response_text[:200]}...")
                            
                            # Create a safe fallback result
                            sub_result = {
                                "sub_id": sub_id,
                                "title": sub_info['title'],
                                "definition": sub_info['definition'],
                                "evidence": f"AI response parsing error: {str(json_err)[:100]}",
                                "status": "Error",
                                "confidence": 0.0,
                                "assessment_reasoning": "JSON parsing failed",
                                "evidence_type_analysis": "Error in processing"
                            }
                            sub_results.append(sub_result)
                        except Exception as parse_err:
                            logging.error(f"  → Unexpected parsing error for {sub_id}: {str(parse_err)}")
                            sub_result = {
                                "sub_id": sub_id,
                                "title": sub_info['title'],
                                "definition": sub_info['definition'],
                                "evidence": f"Unexpected parsing error: {str(parse_err)[:100]}",
                                "status": "Error",
                                "confidence": 0.0,
                                "assessment_reasoning": "Parsing error occurred",
                                "evidence_type_analysis": "Error in processing"
                            }
                            sub_results.append(sub_result)
                        
                    except Exception as sub_error:
                        logging.error(f"  → Error processing sub-requirement {sub_id}: {str(sub_error)}")
                        sub_result = {
                            "sub_id": sub_id,
                            "title": sub_info['title'],
                            "definition": sub_info['definition'],
                            "evidence": f"Processing error: {str(sub_error)[:100]}",
                            "status": "Error",
                            "confidence": 0.0,
                            "assessment_reasoning": "Processing error occurred",
                            "evidence_type_analysis": "Error in processing"
                        }
                        sub_results.append(sub_result)
                
                # Calculate overall control status
                control_result["overall_status"] = calculate_overall_control_status(sub_results)
                control_result["overall_confidence"] = calculate_overall_confidence(sub_results)
                
                # Combine evidence from successful sub-requirements
                evidence_pieces = []
                for r in sub_results:
                    if r['evidence'] != 'No evidence found' and r['status'] != 'Error':
                        # Ensure evidence is a string
                        evidence = str(r['evidence']) if r['evidence'] else 'No evidence found'
                        evidence_pieces.append(evidence)
                
                if evidence_pieces:
                    control_result["overall_evidence"] = " | ".join(evidence_pieces[:2])  # Top 2 pieces
                
                control_result["sub_requirements"] = sub_results
                
                logging.info(f"=== Control {control_id} overall status: {control_result['overall_status']} ===")
            
            results.append(control_result)
        
        logging.info(f'=== Assessment complete - processed {len(results)} controls ===')
        
        return func.HttpResponse(
            json.dumps({"results": results}, indent=2, ensure_ascii=False),
            status_code=200,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )
        
    except json.JSONEncoder as json_error:
        logging.error(f"JSON encoding error: {str(json_error)}")
        return func.HttpResponse(
            json.dumps({
                "error": "JSON encoding error in response",
                "error_type": "JSONError",
                "details": str(json_error)[:200]
            }),
            status_code=500,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS", 
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )
    except Exception as e:
        logging.error(f"Compliance check failed: {str(e)}")
        logging.error(f"Error type: {type(e).__name__}")
        
        # Ensure we return valid JSON even on error
        try:
            error_response = {
                "error": f"Error processing document: {str(e)}",
                "error_type": type(e).__name__,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            return func.HttpResponse(
                json.dumps(error_response),
                status_code=500,
                mimetype="application/json",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            )
        except:
            # Last resort - return plain text error
            return func.HttpResponse(
                '{"error": "Critical error - unable to process request"}',
                status_code=500,
                mimetype="application/json",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            )