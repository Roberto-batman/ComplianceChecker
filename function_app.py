import azure.functions as func
import json
import logging
import os
from openai import AzureOpenAI
import PyPDF2
import io
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = func.FunctionApp()

# NIST AC Controls - subset for MVP
NIST_CONTROLS = {
    "AC-1": {
        "title": "Access Control Policy and Procedures",
        "definition": "(A) The organization develops, documents, and disseminates to personnel or roles with access control responsibilities: (a) An access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and (b) Procedures to facilitate the implementation of the access control policy and associated access controls. (B) The organization reviews and updates the current: (a) Access control policy at least every 3 years; and (b) Access control procedures at least annually."
    },
    "AC-2": {
        "title": "Account Management", 
        "definition": "(A) The organization identifies and selects which types of information system accounts support organizational missions/business functions. (B) The organization assigns account managers for information system accounts. (C) The organization establishes conditions for group and role membership. (D) The organization specifies authorized users of the information system, group and role membership, and access authorizations (i.e., privileges) and other attributes (as required) for each account. (E) The organization requires approvals by responsible managers for requests to create information system accounts. (F) The organization creates, enables, modifies, disables, and removes information system accounts in accordance with information system account management procedures. (G) The organization monitors the use of information system accounts. (H) The organization notifies account managers: (a) When accounts are no longer required; (b) When users are terminated or transferred; and (c) When individual information system usage or need-to-know changes. (I) The organization authorizes access to the information system based on: (a) A valid access authorization; (b) Intended system usage; and (c) Other attributes as required by the organization or associated missions/business functions."
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

def extract_sections_from_page(page_text):
    """Extract section headers from page text"""
    sections = []
    
    # Common patterns for section headers
    patterns = [
        r'^(\d+\.?\d*)\s+([A-Z][A-Za-z\s]+)$',  # "1. Introduction" or "1.1 Purpose"
        r'^([A-Z][A-Z\s]+)$',  # "INTRODUCTION" or "PURPOSE"
        r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)$'   # "Introduction" or "Access Control"
    ]
    
    lines = page_text.split('\n')
    for line_num, line in enumerate(lines):
        line = line.strip()
        if len(line) > 3 and len(line) < 100:  # Reasonable header length
            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    sections.append({
                        "section_number": match.group(1) if len(match.groups()) > 1 else None,
                        "section_title": match.group(2) if len(match.groups()) > 1 else match.group(1),
                        "line_number": line_num + 1
                    })
                    break
    
    return sections

def extract_text_from_pdf(pdf_content):
    """Extract text from PDF with page numbers and metadata"""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_content))
        
        # Extract document metadata
        doc_info = pdf_reader.metadata
        doc_title = "Unknown Document"
        if doc_info:
            doc_title = doc_info.get('/Title', 'Unknown Document')
        
        # Extract text with page tracking
        pages_data = []
        full_text = ""
        
        for page_num, page in enumerate(pdf_reader.pages, 1):
            page_text = page.extract_text()
            if page_text.strip():  # Only add non-empty pages
                pages_data.append({
                    "page_number": page_num,
                    "text": page_text,
                    "sections": extract_sections_from_page(page_text)
                })
                full_text += f"\n[PAGE {page_num}]\n{page_text}\n"
        
        return {
            "document_title": doc_title,
            "full_text": full_text,
            "pages": pages_data,
            "total_pages": len(pdf_reader.pages)
        }
    except Exception as e:
        logging.error(f"Error extracting PDF text: {e}")
        return None

def parse_control_subrequirements(control_id, definition):
    """Parse control definition into individual sub-requirements"""
    # Split definition into logical parts
    parts = re.split(r'(\([A-Z]+\)|\([a-z]+\))', definition)
    parts = [part.strip() for part in parts if part.strip()]
    
    subrequirements = []
    current_stem = None
    
    i = 0
    while i < len(parts):
        part = parts[i]
        
        # Check if this is an uppercase marker like (A), (B), etc.
        upper_match = re.match(r'\(([A-Z]+)\)', part)
        if upper_match:
            # Look ahead to see if there are lowercase sub-parts
            has_lowercase_parts = False
            j = i + 1
            while j < len(parts) and j < i + 10:  # Look ahead reasonably
                if re.match(r'\([a-z]+\)', parts[j]):
                    has_lowercase_parts = True
                    break
                elif re.match(r'\([A-Z]+\)', parts[j]):
                    break
                j += 1
            
            if has_lowercase_parts:
                # This is a stem, store it and continue
                current_stem = {
                    "marker": part,
                    "text": parts[i + 1] if i + 1 < len(parts) else ""
                }
                i += 2
            else:
                # This is a complete requirement
                requirement_text = parts[i + 1] if i + 1 < len(parts) else ""
                subrequirements.append({
                    "id": f"{control_id}{part}",
                    "marker": part,
                    "definition": requirement_text.strip(),
                    "is_complete": True
                })
                i += 2
        
        # Check if this is a lowercase marker like (a), (b), etc.
        elif re.match(r'\([a-z]+\)', part):
            if current_stem:
                # Combine stem with this part
                requirement_text = parts[i + 1] if i + 1 < len(parts) else ""
                full_definition = f"{current_stem['text']} {part} {requirement_text}".strip()
                subrequirements.append({
                    "id": f"{control_id}{current_stem['marker']}{part}",
                    "marker": f"{current_stem['marker']}{part}",
                    "definition": full_definition,
                    "is_complete": True
                })
            i += 2
        else:
            i += 1
    
    # If no sub-requirements found, treat the whole thing as one requirement
    if not subrequirements:
        subrequirements.append({
            "id": control_id,
            "marker": "",
            "definition": definition,
            "is_complete": True
        })
    
    return subrequirements

def find_evidence_with_citations(document_data, control_id, control_definition):
    """Use AI to find evidence with precise citations"""
    try:
        client = AzureOpenAI(
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_key=os.getenv("AZURE_OPENAI_KEY"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION")
        )
        
        # Create a searchable text with page markers
        searchable_text = document_data["full_text"][:8000]  # Limit for token constraints
        
        prompt = f"""
You are a compliance auditor analyzing a policy document for NIST control compliance.

Document: {document_data["document_title"]}
Control: {control_id} - {control_definition}

Document Text with Page Markers:
{searchable_text}

Task: Find specific evidence that addresses this NIST control requirement.

Respond with ONLY valid JSON (no markdown, no code blocks):
{{
    "evidence_items": [
        {{
            "quote": "exact text that provides evidence",
            "page_reference": "page number where found (look for [PAGE X] markers)",
            "relevance_score": 0.9,
            "section_context": "section name or context where found"
        }}
    ],
    "overall_compliance": "Fully Meets|Partially Meets|Does Not Meet",
    "compliance_reasoning": "brief explanation of assessment",
    "confidence_score": 0.85
}}

Instructions:
- Find 1-3 most relevant evidence quotes
- Use exact text from the document
- Note the page number from [PAGE X] markers
- Score relevance 0.0-1.0 based on how well it addresses the control
- Overall confidence 0.0-1.0 in your assessment
"""

        response = client.chat.completions.create(
            model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity compliance auditor focused on precise evidence extraction."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=800
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
                "evidence_items": [],
                "overall_compliance": "Error",
                "compliance_reasoning": f"Could not parse AI response: {str(e)}",
                "confidence_score": 0.0
            }
        
    except Exception as e:
        logging.error(f"Error in evidence extraction for {control_id}: {e}")
        return {
            "evidence_items": [],
            "overall_compliance": "Error", 
            "compliance_reasoning": f"Processing error: {str(e)}",
            "confidence_score": 0.0
        }

@app.route(route="ComplianceChecker", auth_level=func.AuthLevel.ANONYMOUS)
def ComplianceChecker(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('NIST Compliance Checker triggered')
    
        
    # Debug environment variables FIRST
    import os
    logging.info(f"DEBUG - AZURE_OPENAI_ENDPOINT: {os.environ.get('AZURE_OPENAI_ENDPOINT', 'NOT_FOUND')}")
    logging.info(f"DEBUG - AZURE_OPENAI_DEPLOYMENT: {os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'NOT_FOUND')}")
    logging.info(f"DEBUG - Key exists: {'YES' if os.environ.get('AZURE_OPENAI_KEY') else 'NO'}")
    

    # Debug environment variables
    import os
    logging.info(f"AZURE_OPENAI_ENDPOINT: {os.environ.get('AZURE_OPENAI_ENDPOINT', 'NOT_FOUND')}")
    logging.info(f"AZURE_OPENAI_DEPLOYMENT: {os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'NOT_FOUND')}")
    logging.info(f"AZURE_OPENAI_API_VERSION: {os.environ.get('AZURE_OPENAI_API_VERSION', 'NOT_FOUND')}")
    logging.info(f"AZURE_OPENAI_KEY exists: {'YES' if os.environ.get('AZURE_OPENAI_KEY') else 'NO'}")











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
        
        # Extract text and metadata from PDF
        document_data = extract_text_from_pdf(pdf_content)
        if not document_data:
            return func.HttpResponse(
                json.dumps({"error": "Could not extract text from PDF"}),
                status_code=400,
                mimetype="application/json",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            )
        
        # Check compliance for each control with enhanced citations
        results = []
        for control_id, control_info in NIST_CONTROLS.items():
            logging.info(f"Checking compliance for {control_id}")
            
            # Parse sub-requirements
            subrequirements = parse_control_subrequirements(control_id, control_info["definition"])
            
            # Assess each sub-requirement individually
            subreq_results = []
            for subreq in subrequirements:
                evidence_result = find_evidence_with_citations(
                    document_data, 
                    subreq["id"], 
                    subreq["definition"]
                )
                
                subreq_results.append({
                    "subreq_id": subreq["id"],
                    "subreq_marker": subreq["marker"],
                    "subreq_definition": subreq["definition"],
                    "evidence_items": evidence_result.get("evidence_items", []),
                    "compliance_status": evidence_result.get("overall_compliance", "Error"),
                    "reasoning": evidence_result.get("compliance_reasoning", ""),
                    "confidence_score": evidence_result.get("confidence_score", 0.0)
                })
            
            # Calculate overall control compliance
            sub_statuses = [sr["compliance_status"] for sr in subreq_results if sr["compliance_status"] != "Error"]
            if not sub_statuses:
                overall_status = "Error"
            elif all(status == "Fully Meets" for status in sub_statuses):
                overall_status = "Fully Meets"
            elif any(status in ["Fully Meets", "Partially Meets"] for status in sub_statuses):
                overall_status = "Partially Meets"
            else:
                overall_status = "Does Not Meet"
            
            # Calculate overall confidence (average of sub-requirements)
            confidences = [sr["confidence_score"] for sr in subreq_results if sr["confidence_score"] > 0]
            overall_confidence = sum(confidences) / len(confidences) if confidences else 0.0
            
            results.append({
                "control_id": control_id,
                "title": control_info["title"],
                "definition": control_info["definition"],
                "document_title": document_data["document_title"],
                "subrequirements": subreq_results,
                "overall_compliance_status": overall_status,
                "overall_confidence_score": overall_confidence
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
        import os
        debug_info = {
            "error": f"Error processing document: {str(e)}",
            "debug": {
                "endpoint": os.environ.get('AZURE_OPENAI_ENDPOINT', 'NOT_FOUND'),
                "deployment": os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'NOT_FOUND'),
                "api_version": os.environ.get('AZURE_OPENAI_API_VERSION', 'NOT_FOUND'),
                "key_exists": 'YES' if os.environ.get('AZURE_OPENAI_KEY') else 'NO'
            }
        }
        logging.error(f"Compliance check failed: {str(e)}")
        return func.HttpResponse(
            json.dumps(debug_info),
            status_code=500,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )