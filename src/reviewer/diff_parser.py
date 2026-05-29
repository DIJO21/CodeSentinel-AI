import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class DiffParser:
    @staticmethod
    def parse_unified_diff(diff_str: str) -> List[Dict[str, Any]]:
        """
        Parses a raw unified git diff into structured file modifications.
        Tracks changes, specific lines added, and code context.
        """
        files: List[Dict[str, Any]] = []
        current_file: Optional[Dict[str, Any]] = None
        current_hunk: Optional[Dict[str, Any]] = None
        
        # Line trackers
        new_line_num = 0
        
        lines = diff_str.splitlines()
        for line in lines:
            # File headers
            if line.startswith("diff --git"):
                if current_file:
                    files.append(current_file)
                current_file = {
                    "filename": "",
                    "additions": [],
                    "raw_diff": []
                }
                current_file["raw_diff"].append(line)
                continue
                
            if current_file is None:
                continue
                
            current_file["raw_diff"].append(line)
            
            if line.startswith("--- a/"):
                continue
            if line.startswith("+++ b/"):
                current_file["filename"] = line[6:]
                continue
                
            # Hunk headers: @@ -old_start,old_len +new_start,new_len @@
            hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if hunk_match:
                new_line_num = int(hunk_match.group(1))
                continue
                
            # Line changes
            if line.startswith("+") and not line.startswith("+++"):
                current_file["additions"].append({
                    "line_number": new_line_num,
                    "content": line[1:]
                })
                new_line_num += 1
            elif line.startswith("-") and not line.startswith("---"):
                # Line was deleted, line number in new file doesn't increment
                continue
            else:
                # Unchanged context line
                new_line_num += 1
                
        if current_file:
            files.append(current_file)
            
        logger.info("Parsed %d file modifications from Git diff.", len(files))
        return files
