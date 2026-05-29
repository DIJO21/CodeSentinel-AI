import logging
from typing import Dict, Any
from arq import cron
from src.backend.config import settings
from src.reviewer.engine import ReviewEngine
from src.backend.observability import REVIEW_COMPLETED

logger = logging.getLogger(__name__)

async def run_async_code_review(ctx: Dict[str, Any], diff_str: str, repo_fullname: str, pr_number: int) -> Dict[str, Any]:
    """
    Background worker task that analyzes a repository PR diff using the AI Review Engine.
    """
    logger.info("Starting background review for %s PR #%d", repo_fullname, pr_number)
    
    try:
        # Obtain Anthropic key from global settings
        api_key = settings.anthropic_api_key
        engine = ReviewEngine(api_key=api_key)
        
        findings = await engine.analyze_diff(diff_str)
        
        # Increment metrics
        REVIEW_COMPLETED.labels(status="success").inc()
        
        logger.info("Successfully completed review task for %s PR #%d. Found %d issues.", repo_fullname, pr_number, len(findings))
        return {
            "status": "completed",
            "repo": repo_fullname,
            "pr_number": pr_number,
            "findings": findings
        }
    except Exception as e:
        REVIEW_COMPLETED.labels(status="failure").inc()
        logger.error("Async review task failed for %s PR #%d: %s", repo_fullname, pr_number, str(e))
        return {
            "status": "failed",
            "error": str(e)
        }

class WorkerSettings:
    """
    Configuration parameters required by ARQ worker command line interfaces.
    """
    functions = [run_async_code_review]
    redis_settings = None # Uses default connection parameters unless overridden
    
    @classmethod
    async def on_startup(cls, ctx: Dict[str, Any]) -> None:
        logger.info("CodeSentinel worker pool starting up...")

    @classmethod
    async def on_shutdown(cls, ctx: Dict[str, Any]) -> None:
        logger.info("CodeSentinel worker pool shutting down...")
