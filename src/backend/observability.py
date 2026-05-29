import logging
import sys
import structlog
from prometheus_client import Counter, Histogram, CollectorRegistry

# Prometheus Metrics
registry = CollectorRegistry()

HTTP_REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests received",
    ["method", "endpoint", "http_status"],
    registry=registry
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["endpoint"],
    registry=registry
)

REVIEW_COMPLETED = Counter(
    "code_reviews_completed_total",
    "Total review evaluations run",
    ["status"],
    registry=registry
)

def setup_logging() -> None:
    """
    Sets up structlog configuration for production-grade logging.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )
    
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
