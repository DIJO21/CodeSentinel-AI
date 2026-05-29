import logging
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
from src.crawler.base import BaseCrawler

logger = logging.getLogger(__name__)

class MitreCrawler(BaseCrawler):
    def __init__(self) -> None:
        super().__init__(base_url="https://cwe.mitre.org/data/definitions/")

    async def get_cwe_details(self, cwe_id: int) -> Optional[Dict[str, Any]]:
        """
        Crawls MITRE CWE website for detailed information regarding a specific CWE identifier.
        """
        url = f"{cwe_id}.html"
        try:
            html = await self.fetch(url, response_format="text")
            if not html:
                return None
            
            soup = BeautifulSoup(html, "html.parser")
            
            # Extract basic description and title
            title_node = soup.find("h2")
            title = title_node.text.strip() if title_node else f"CWE-{cwe_id}"
            
            desc_div = soup.find("div", {"id": "Description"})
            description = ""
            if desc_div:
                desc_text_node = desc_div.find("div", {"class": "detail"})
                description = desc_text_node.text.strip() if desc_text_node else desc_div.text.strip()
                
            # Parse mitigation strategies if present
            mitigations = []
            mit_div = soup.find("div", {"id": "Potential_Mitigations"})
            if mit_div:
                table = mit_div.find("table")
                if table:
                    rows = table.find_all("tr")
                    for row in rows:
                        cells = row.find_all("td")
                        if len(cells) >= 2:
                            mitigations.append({
                                "phase": cells[0].text.strip(),
                                "strategy": cells[1].text.strip()
                            })

            return {
                "cwe_id": cwe_id,
                "title": title,
                "description": description,
                "mitigations": mitigations
            }
        except Exception as e:
            logger.error("Failed to parse CWE-%d: %s", cwe_id, str(e))
            return None
