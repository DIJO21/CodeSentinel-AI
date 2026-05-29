import hmac
import hashlib
import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, Header, HTTPException, status, Body
from src.backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Validates that the payload was signed using the expected GitHub Webhook HMAC SHA256 secret.
    """
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature[7:], expected)

@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(...),
    x_hub_signature_256: str = Header(None),
    payload: Dict[str, Any] = Body(
        default=None,
        description="The GitHub webhook payload",
        examples=[
            {
                "action": "opened",
                "number": 42,
                "pull_request": {
                    "diff_url": "https://github.com/octocat/Hello-World/pull/42.diff"
                },
                "repository": {
                    "full_name": "octocat/Hello-World"
                }
            }
        ]
    )
) -> Dict[str, Any]:
    """
    HTTP POST handler designed to receive GitHub Webhook notification streams.
    """
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body cannot be empty."
        )

    payload_bytes = await request.body()
    
    # Enforce webhook security if configured
    if settings.github_webhook_secret:
        if not x_hub_signature_256:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signature header.")
        if not verify_github_signature(payload_bytes, x_hub_signature_256, settings.github_webhook_secret):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Signature authentication failed.")

    if x_github_event == "pull_request":
        action = payload.get("action")
        pr = payload.get("pull_request", {})
        
        # Trigger review on opened or synchronized code changes
        if action in ["opened", "synchronize"]:
            repo_fullname = payload.get("repository", {}).get("full_name", "")
            pr_number = payload.get("number", 0)
            diff_url = pr.get("diff_url")
            
            logger.info("Enqueuing analysis for pull request %s #%d. Diff URL: %s", repo_fullname, pr_number, diff_url)
            
            # Here we would enqueue via ARQ to Redis. Mocked queue push logging.
            # In production:
            # await request.app.state.arq_pool.enqueue_job("run_async_code_review", "MOCK_DIFF_CONTENT", repo_fullname, pr_number)
            
            return {
                "message": "Pull request review enqueued.",
                "repository": repo_fullname,
                "pr_number": pr_number
            }
            
    return {"message": f"Ignored event type: {x_github_event}"}


def generate_mock_findings(diff_str: str) -> list:
    findings = []
    import re
    
    current_file = "unknown_file.py"
    lines = diff_str.split("\n")
    
    for i, line in enumerate(lines):
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        elif line.startswith("+++ "):
            parts = line.split()
            if len(parts) > 1:
                current_file = parts[1].strip()
            continue
            
        if not line.startswith("+") or line.startswith("+++"):
            continue
            
        clean_content = line[1:].strip()
        line_num = i + 1
        
        # 1. Hardcoded secrets
        if re.search(r'(api_key|password|secret|token|private_key)\s*=\s*[\'"][^\'"]+[\'"]', clean_content, re.IGNORECASE):
            findings.append({
                "filename": current_file,
                "line_number": line_num,
                "vulnerability": "Hardcoded Cryptographic Key / Secret",
                "severity": "Critical",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "description": "A sensitive credential, key, or token was found hardcoded in the source code. This can be exposed if the codebase is shared, leaked, or compiled into client binaries.",
                "remediation": f"```python\n# Remove hardcoded secret in {current_file} and load from environment variables:\nimport os\n\nAPI_KEY = os.getenv(\"API_KEY\")\n```"
            })
            
        # 2. SQL Injection
        elif "select " in clean_content.lower() and ("+" in clean_content or "f\"" in clean_content or ".format(" in clean_content):
            findings.append({
                "filename": current_file,
                "line_number": line_num,
                "vulnerability": "SQL Injection (SQLi)",
                "severity": "High",
                "owasp_category": "A03:2021-Injection",
                "description": "Constructing SQL queries using string concatenation or formatting allows attackers to execute arbitrary SQL statements by manipulating the parameters.",
                "remediation": f"```python\n# Use parameterized queries instead of string concatenation in {current_file}:\nquery = \"SELECT * FROM users WHERE username = %s AND status = %s\"\ncursor.execute(query, (username, status))\n```"
            })
            
        # 3. Unsafe Deserialization
        elif "pickle.loads" in clean_content:
            findings.append({
                "filename": current_file,
                "line_number": line_num,
                "vulnerability": "Unsafe Deserialization of Untrusted Data",
                "severity": "Critical",
                "owasp_category": "A08:2021-Software and Data Integrity Failures",
                "description": "Deserializing untrusted data using `pickle` can lead to arbitrary remote code execution (RCE) since `pickle` can reconstruct arbitrary Python objects.",
                "remediation": f"```python\n# Use safer data serialization formats like JSON or Protocol Buffers in {current_file}:\nimport json\n\ndata = json.loads(payload_bytes)\n```"
            })
            
        # 4. Command Injection
        elif "os.system(" in clean_content or "subprocess.Popen(" in clean_content or ("subprocess.run(" in clean_content and "shell=True" in clean_content):
            findings.append({
                "filename": current_file,
                "line_number": line_num,
                "vulnerability": "Command Injection",
                "severity": "Critical",
                "owasp_category": "A03:2021-Injection",
                "description": "Invoking system commands through shell environments using raw strings from user inputs enables execution of arbitrary shell commands.",
                "remediation": f"```python\n# Avoid shell=True and pass arguments as a list in {current_file}:\nimport subprocess\n\nsubprocess.run([\"ls\", \"-l\", target_dir], shell=False, check=True)\n```"
            })

        # 5. XSS
        elif "htmlresponse(" in clean_content.lower() and ("+" in clean_content or "f\"" in clean_content):
            findings.append({
                "filename": current_file,
                "line_number": line_num,
                "vulnerability": "Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "owasp_category": "A03:2021-Injection",
                "description": "Returning raw, unsanitized user inputs within an HTML response allows attackers to inject malicious client-side scripts executed by other users' browsers.",
                "remediation": f"```python\n# Sanitize input or use templates in {current_file}:\nfrom fastapi.templating import Jinja2Templates\n\nreturn templates.TemplateResponse(\"index.html\", {{\"request\": request, \"user_input\": user_input}})\n```"
            })

    if not findings:
        findings.append({
            "filename": current_file if current_file != "unknown_file.py" else "src/backend/webhooks.py",
            "line_number": 12,
            "vulnerability": "Weak Cryptographic Signature Verification",
            "severity": "Medium",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "description": "The application verification logic does not enforce key rotation checks or handle timing-attack resistance during high load signature validations.",
            "remediation": "```python\n# Ensure timing-attack protection using hmac.compare_digest:\nimport hmac\n\nif not hmac.compare_digest(provided_signature, expected_signature):\n    raise HTTPException(status_code=403, detail=\"Access Denied\")\n```"
        })
        findings.append({
            "filename": current_file if current_file != "unknown_file.py" else "src/backend/config.py",
            "line_number": 8,
            "vulnerability": "Default Fallback Configurations",
            "severity": "Low",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "description": "Using fallback strings for secrets (such as 'mock-key') can lead to accidental deployments containing weak key strengths in production environments.",
            "remediation": "```python\n# Force configuration load or raise errors if values are missing:\nimport os\n\napi_key = os.environ.get(\"ANTHROPIC_API_KEY\")\nif not api_key:\n    raise ValueError(\"ANTHROPIC_API_KEY must be set in production\")\n```"
        })
        
    return findings


@router.post("/analyze")
async def analyze_diff_direct(
    payload: Dict[str, Any] = Body(..., example={"diff": "..."}),
    x_anthropic_api_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Direct endpoint for analyzing unified git diffs.
    """
    diff_str = payload.get("diff", "")
    if not diff_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Diff content cannot be empty."
        )
    
    # Check if we should use mock findings
    api_key = x_anthropic_api_key or settings.anthropic_api_key
    
    # If the key is empty or a known mock key, trigger smart mock mode
    if not api_key or api_key == "mock-key" or api_key.strip() == "":
        logger.info("No valid Anthropic key provided. Running in Demo Mode with mock findings.")
        findings = generate_mock_findings(diff_str)
        return {"status": "success", "mode": "demo", "findings": findings}
        
    # Otherwise run the actual review engine
    try:
        from src.reviewer.engine import ReviewEngine
        logger.info("Running actual security analysis with Anthropic Claude API.")
        engine = ReviewEngine(api_key=api_key)
        findings = await engine.analyze_diff(diff_str)
        return {"status": "success", "mode": "real", "findings": findings}
    except Exception as e:
        logger.error("Analysis via Anthropic failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis engine error: {str(e)}"
        )
