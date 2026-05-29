import pytest
from src.crawler.mitre import MitreCrawler
from src.crawler.owasp import OwaspCrawler

@pytest.mark.asyncio
async def test_mitre_cwe_crawler_mock() -> None:
    # Instantiate crawler
    crawler = MitreCrawler()
    # Test fallback check or mock behaviors
    assert crawler.base_url == "https://cwe.mitre.org/data/definitions/"

@pytest.mark.asyncio
async def test_owasp_crawler_fallback() -> None:
    crawler = OwaspCrawler()
    categories = await crawler.get_top_10()
    assert len(categories) > 0
    assert any(c["identifier"] == "A01:2021" for c in categories)
