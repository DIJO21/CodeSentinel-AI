import json
import logging
from typing import List, Dict, Any, Optional
from anthropic import AsyncAnthropic
from src.reviewer.diff_parser import DiffParser

logger = logging.getLogger(__name__)

class ReviewEngine:
    def __init__(self, api_key: str) -> None:
        self.client = AsyncAnthropic(api_key=api_key)

    async def analyze_diff(self, diff_str: str) -> List[Dict[str, Any]]:
        """
        Parses a Git diff and runs code review on all additions using Claude.
        """
        parsed_files = DiffParser.parse_unified_diff(diff_str)
        findings: List[Dict[str, Any]] = []
        
        for file_info in parsed_files:
            filename = file_info["filename"]
            additions = file_info["additions"]
            
            if not additions:
                continue
                
            # Construct code segment with line context
            code_segment = "\n".join([f"{item['line_number']}: {item['content']}" for item in additions])
            
            # Request scan from Claude
            file_findings = await self._scan_code_segment(filename, code_segment)
            findings.extend(file_findings)
            
        return findings

    async def _scan_code_segment(self, filename: str, code_segment: str) -> List[Dict[str, Any]]:
        """
        Invokes Claude API to extract structured vulnerability reports.
        """
        prompt = (
            f"You are an Elite DevSecOps AI reviewer. Analyze the following code changes in the file '{filename}' "
            f"for security vulnerabilities (specifically OWASP Top 10, injections, hardcoded credentials/secrets, path traversal, "
            f"race conditions, null dereferences, and unsafe deserialization).\n\n"
            f"Code changes:\n{code_segment}\n\n"
            f"Return a JSON array containing findings. If no issues are found, return an empty array [].\n"
            f"Each finding object MUST follow this Pydantic-compatible JSON schema structure:\n"
            f"{{\n"
            f"  \"filename\": \"{filename}\",\n"
            f"  \"line_number\": <int>,\n"
            f"  \"vulnerability\": \"<short name>\",\n"
            f"  \"severity\": \"<Low|Medium|High|Critical>\",\n"
            f"  \"owasp_category\": \"<OWASP Category e.g., A03:2021-Injection>\",\n"
            f"  \"description\": \"<explanation of why this is a risk>\",\n"
            f"  \"remediation\": \"<code block or instructions to fix this issue>\"\n"
            f"}}\n"
            f"Ensure output contains ONLY valid JSON inside a code block."
        )

        try:
            logger.info("Requesting security analysis from Anthropic Claude for %s...", filename)
            response = await self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.0,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract JSON block
            raw_text = response.content[0].text
            json_match = re.search(r"\[\s*\{.*\}\s*\]|\[\s*\]", raw_text, re.DOTALL)
            if json_match:
                parsed_json = json.loads(json_match.group(0))
                if isinstance(parsed_json, list):
                    return parsed_json
            else:
                # Fallback check if text is clean JSON without brackets
                parsed_json = json.loads(raw_text.strip())
                if isinstance(parsed_json, list):
                    return parsed_json
            logger.warning("Failed to extract valid JSON array format from model output for %s.", filename)
        except Exception as e:
            logger.error("Vulnerability scan failed for %s: %s", filename, str(e))
        return []

import re
