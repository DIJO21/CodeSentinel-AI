import time
import logging
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from arq import create_pool
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os
from src.backend.config import settings
from src.backend.webhooks import router as webhook_router
from src.backend.observability import setup_logging, HTTP_REQUEST_COUNT, REQUEST_LATENCY

logger = logging.getLogger(__name__)

# Config application logging
setup_logging()

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach routes
app.include_router(webhook_router, prefix="/api/v1")

# Serve frontend files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

# Serve static directory (CSS, JS, assets)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index() -> HTMLResponse:
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>CodeSentinel AI static frontend is currently being built. Please check back in a few seconds!</h1>")


@app.middleware("http")
async def monitor_requests(request: Request, call_next):
    """
    Middleware measuring API endpoint response latency and request volume.
    """
    start_time = time.time()
    response = await call_next(request)
    
    duration = time.time() - start_time
    path = request.url.path
    
    # Update metrics registries
    HTTP_REQUEST_COUNT.labels(method=request.method, endpoint=path, http_status=response.status_code).inc()
    REQUEST_LATENCY.labels(endpoint=path).observe(duration)
    
    return response

@app.on_event("startup")
async def startup_event() -> None:
    logger.info("Starting up CodeSentinel API backend...")
    try:
        # Establish background worker queue pool connections
        from arq.connections import RedisSettings
        # In a real environment, load host/port from settings.redis_url
        app.state.arq_pool = await create_pool()
        logger.info("Successfully connected to Redis ARQ task queue.")
    except Exception as e:
        logger.error("Failed to connect to Redis ARQ queue: %s. Background worker execution disabled.", str(e))

@app.on_event("shutdown")
async def shutdown_event() -> None:
    logger.info("Shutting down CodeSentinel API backend...")
    if hasattr(app.state, "arq_pool") and app.state.arq_pool:
        await app.state.arq_pool.close()

@app.get("/metrics")
def get_metrics() -> Response:
    """
    Exposes Prometheus-scrappable runtime metrics.
    """
    from src.backend.observability import registry
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
def health_check() -> dict:
    """
    Exposes health indicator check statuses.
    """
    return {"status": "healthy", "service": "codesentinel-ai"}
