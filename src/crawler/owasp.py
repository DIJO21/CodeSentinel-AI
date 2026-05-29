import logging
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from src.crawler.base import BaseCrawler

logger = logging.getLogger(__name__)

class OwaspCrawler(BaseCrawler):
    def __init__(self) -> None:
        super().__init__(base_url="https://owasp.org/www-project-top-ten/")

    async def get_top_10(self) -> List[Dict[str, Any]]:
        """
        Crawls and parses the main OWASP Top 10 category pages.
        """
        try:
            html = await self.fetch("", response_format="text")
            if not html:
                return []
            
            soup = BeautifulSoup(html, "html.parser")
            categories: List[Dict[str, Any]] = []
            
            # Find the main navigation or headers listing the current Top 10
            # OWASP lists them inside tags under content
            main_content = soup.find("section", {"id": "main_content"})
            if not main_content:
                main_content = soup
                
            links = main_content.find_all("a")
            for link in links:
                text = link.text.strip()
                href = link.get("href", "")
                if "A0" in text and href.startswith("A"):
                    categories.append({
                        "identifier": text.split(":")[0].strip() if ":" in text else text,
                        "name": text,
                        "url": f"https://owasp.org/www-project-top-ten/{href}"
                    })
            
            # Fallback to defaults if page layout has changed dramatically
            if not categories:
                categories = [
                    {"identifier": "A01:2021", "name": "Broken Access Control", "url": "https://owasp.org/www-project-top-ten/A01_2021-Broken_Access_Control/"},
                    {"identifier": "A02:2021", "name": "Cryptographic Failures", "url": "https://owasp.org/www-project-top-ten/A02_2021-Cryptographic_Failures/"},
                    {"identifier": "A03:2021", "name": "Injection", "url": "https://owasp.org/www-project-top-ten/A03_2021-Injection/"},
                    {"identifier": "A04:2021", "name": "Insecure Design", "url": "https://owasp.org/www-project-top-ten/A04_2021-Insecure_Design/"},
                    {"identifier": "A05:2021", "name": "Security Misconfiguration", "url": "https://owasp.org/www-project-top-ten/A05_2021-Security_Misconfiguration/"},
                    {"identifier": "A06:2021", "name": "Vulnerable and Outdated Components", "url": "https://owasp.org/www-project-top-ten/A06_2021-Vulnerable_and_Outdated_Components/"},
                    {"identifier": "A07:2021", "name": "Identification and Authentication Failures", "url": "https://owasp.org/www-project-top-ten/A07_2021-Identification_and_Authentication_Failures/"},
                    {"identifier": "A08:2021", "name": "Software and Data Integrity Failures", "url": "https://owasp.org/www-project-top-ten/A08_2021-Software_and_Data_Integrity_Failures/"},
                    {"identifier": "A09:2021", "name": "Security Logging and Monitoring Failures", "url": "https://owasp.org/www-project-top-ten/A09_2021-Security_Logging_and_Monitoring_Failures/"},
                    {"identifier": "A10:2021", "name": "Server-Side Request Forgery", "url": "https://owasp.org/www-project-top-ten/A10_2021-Server-Side_Request_Forgery/"},
                ]
            return categories
        except Exception as e:
            logger.error("Failed to crawl OWASP Top 10: %s", str(e))
            return []
