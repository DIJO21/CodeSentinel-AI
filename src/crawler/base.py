import asyncio
import logging
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger(__name__)

class BaseCrawler:
    def __init__(self, base_url: Optional[str] = None, rate_limit_delay: float = 1.0, max_retries: int = 3) -> None:
        self.base_url: Optional[str] = base_url
        self.rate_limit_delay: float = rate_limit_delay
        self.max_retries: int = max_retries
        self.headers: Dict[str, str] = {
            "User-Agent": "CodeSentinelAI/1.0.0 (DevSecOps Crawler Engine)",
            "Accept": "application/json, text/html, */*",
        }

    async def fetch(self, url: str, params: Optional[Dict[str, Any]] = None, response_format: str = "text") -> Any:
        target_url = f"{self.base_url}{url}" if self.base_url and not url.startswith("http") else url
        
        async with httpx.AsyncClient(headers=self.headers, follow_redirects=True, timeout=30.0) as client:
            for attempt in range(self.max_retries):
                try:
                    await asyncio.sleep(self.rate_limit_delay)
                    response = await client.get(target_url, params=params)
                    response.raise_for_status()
                    
                    if response_format == "json":
                        return response.json()
                    elif response_format == "bytes":
                        return response.content
                    return response.text
                except (httpx.HTTPStatusError, httpx.RequestError) as e:
                    logger.warning(
                        "Attempt %d/%d failed for URL %s. Error: %s",
                        attempt + 1, self.max_retries, target_url, str(e)
                    )
                    if attempt == self.max_retries - 1:
                        raise e
                    await asyncio.sleep(self.rate_limit_delay * (2 ** attempt))
        return None
