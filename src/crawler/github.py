import os
import shutil
import logging
from typing import List, Dict, Any, Optional
import git
from src.crawler.base import BaseCrawler

logger = logging.getLogger(__name__)

class GitHubMiner(BaseCrawler):
    def __init__(self, token: Optional[str] = None) -> None:
        super().__init__()
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def clone_repository(self, repo_url: str, dest_dir: str) -> git.Repo:
        """
        Clones a target repository to local storage for mining or dataset loading.
        """
        if os.path.exists(dest_dir):
            logger.info("Destination directory %s exists. Removing first.", dest_dir)
            shutil.rmtree(dest_dir)
            
        logger.info("Cloning repository %s to %s...", repo_url, dest_dir)
        repo = git.Repo.clone_from(repo_url, dest_dir)
        logger.info("Successfully cloned %s.", repo_url)
        return repo

    def extract_vulnerability_patches(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Extracts code patches from commits that reference security issues (fix, vuln, CVE, security, bug).
        """
        repo = git.Repo(repo_path)
        patches: List[Dict[str, Any]] = []
        keywords = ["fix", "vuln", "cve", "security", "bug", "exploit", "patch"]
        
        # Traverse commits on active branch
        for commit in repo.iter_commits():
            msg = commit.message.lower()
            if any(keyword in msg for keyword in keywords):
                # Ensure we have parent commits to compare
                if not commit.parents:
                    continue
                
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)
                
                for d in diffs:
                    if d.a_path and d.a_path.endswith((".py", ".js", ".java", ".c", ".cpp", ".go", ".rs")):
                        try:
                            diff_text = d.diff.decode("utf-8", errors="ignore")
                            patches.append({
                                "commit_hash": commit.hexsha,
                                "message": commit.message.strip(),
                                "file_path": d.a_path,
                                "diff": diff_text,
                                "author": commit.author.name,
                                "date": commit.committed_datetime.isoformat(),
                            })
                        except Exception as e:
                            logger.error("Failed to parse diff: %s", str(e))
        return patches

    async def get_github_advisories(self, severity: str = "critical") -> List[Dict[str, Any]]:
        """
        Queries the GitHub Security Advisory API to fetch public advisory records.
        """
        url = "https://api.github.com/advisories"
        params = {"severity": severity, "per_page": 100}
        try:
            res = await self.fetch(url, params=params, response_format="json")
            if isinstance(res, list):
                return res
        except Exception as e:
            logger.error("Failed to retrieve advisories from GitHub API: %s", str(e))
        return []
