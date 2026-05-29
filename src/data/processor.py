import json
import logging
from typing import List, Dict, Any, Tuple
import re

logger = logging.getLogger(__name__)

class DataProcessor:
    def __init__(self) -> None:
        self.owasp_mappings = {
            r"(sql|ldap|xpath|cmd|exec|eval|command|injection)": "A03:2021-Injection",
            r"(auth|login|password|session|credential|token|jwt)": "A07:2021-Identification and Authentication Failures",
            r"(xss|cross-site|csrf|xsrf)": "A08:2021-Software and Data Integrity Failures",
            r"(path|directory|traversal|file|upload|ssrf|request-forgery)": "A10:2021-Server-Side Request Forgery",
            r"(crypto|encrypt|decrypt|hash|cipher|ssl|tls|md5|sha1)": "A02:2021-Cryptographic Failures",
            r"(permission|privilege|access|rbac|abac|authorize)": "A01:2021-Broken Access Control",
            r"(cors|config|port|debug|header)": "A05:2021-Security Misconfiguration",
            r"(overflow|null|ptr|dereference|leak|uaf|double-free)": "A04:2021-Insecure Design"
        }

    def normalize_record(self, raw_data: Dict[str, Any], source: str) -> Dict[str, Any]:
        """
        Standardizes vulnerability records from multiple sources into a single schema.
        """
        code = raw_data.get("code") or raw_data.get("diff") or raw_data.get("func") or ""
        msg = raw_data.get("message") or raw_data.get("description") or raw_data.get("msg") or ""
        label = 1 if raw_data.get("label") == 1 or raw_data.get("vuln") is True else 0
        
        # Deduce OWASP category using regex on message / code context
        owasp_cat = "Unclassified"
        for pattern, category in self.owasp_mappings.items():
            if re.search(pattern, msg.lower()) or re.search(pattern, code.lower()):
                owasp_cat = category
                break
                
        return {
            "source": source,
            "code_sample": code,
            "description": msg,
            "is_vulnerable": label,
            "owasp_category": owasp_cat,
            "metadata": {
                "commit": raw_data.get("commit_hash"),
                "file_path": raw_data.get("file_path"),
                "cwe": raw_data.get("cwe")
            }
        }

    def deduplicate(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Removes identical code samples to prevent data leakage between train and test splits.
        """
        seen_code = set()
        deduped = []
        for r in records:
            code_hash = hash(r["code_sample"].strip())
            if code_hash not in seen_code:
                seen_code.add(code_hash)
                deduped.append(r)
        logger.info("Deduplication reduced records from %d to %d.", len(records), len(deduped))
        return deduped

    def train_validation_test_split(
        self, records: List[Dict[str, Any]], train_ratio: float = 0.8, val_ratio: float = 0.1
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]:
        """
        Splits dataset into training, validation, and test datasets.
        """
        import random
        # Ensure splits are repeatable
        random.seed(42)
        shuffled = list(records)
        random.shuffle(shuffled)
        
        total = len(shuffled)
        train_end = int(total * train_ratio)
        val_end = train_end + int(total * val_ratio)
        
        train = shuffled[:train_end]
        val = shuffled[train_end:val_end]
        test = shuffled[val_end:]
        
        logger.info("Split datasets: Train=%d, Val=%d, Test=%d", len(train), len(val), len(test))
        return train, val, test
