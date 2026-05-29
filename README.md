# CodeSentinel AI

CodeSentinel AI is a production-grade, AI-powered Context-Aware Code Review and DevSecOps Analysis Platform. It runs autonomous data scraping pipelines to extract vulnerability datasets, fine-tunes deep learning sequence classifiers on GPUs (supporting dynamic Google Colab hardware optimizations), and hosts an asynchronous FastAPI backend integrated with Redis, ARQ workers, and the Anthropic Claude API for scanning git pull requests.

It also features a beautiful, glassmorphic **Security Review Dashboard** for auditing unified git diffs directly in the browser.

---

## 🚀 Key Features

* **Interactive Web Dashboard**: A single-page, glassmorphic dark-mode interface at `/` for submitting unified diffs, viewing visual statistics (Critical, High, Medium, and Low issues), filtering findings, and seeing remediation diff comparisons.
* **Interactive Demo Mode**: Out-of-the-box local vulnerability scanning (no API key required) that matches code patterns (SQL injection, unsafe deserialization, command injection, hardcoded credentials) to generate realistic DevSecOps feedback.
* **Autonomous Crawlers**: Crawls MITRE CWE lists, OWASP Top 10 repositories, and parses raw Git histories for code vulnerabilities.
* **GPU Training Optimizer**: Detects A100, V100, or T4 GPU architectures and tunes fp16/bf16 precision, gradient checkpointing, `torch.compile()`, and QLoRA quantization settings automatically.
* **Async Code Review Engine**: Integrates with the Anthropic SDK to read unified Git diff blocks, identify vulnerabilities, and map weaknesses directly to OWASP categories.
* **Event-Driven Backend**: Implements a FastAPI application with verified HMAC signatures for GitHub webhook ingestion and schedules background reviews via Redis/ARQ tasks.
* **Observability Registry**: Built-in structured JSON loggers (`structlog`) and Prometheus indicators monitoring HTTP latencies and review completions.

---

## 📂 Repository Layout

```
CodeSentinel AI/
├── .github/workflows/   # CI/CD pipelines
├── docker/              # Docker deployment blueprints
├── notebooks/           # Jupyter notebooks optimized for Google Colab
├── src/
│   ├── backend/         # FastAPI, endpoints, and telemetry configurations
│   │   ├── static/      # Frontend SPA assets
│   │   │   ├── css/     # CSS styles (glassmorphic theme)
│   │   │   ├── js/      # Frontend state & rendering logic
│   │   │   └── index.html
│   │   ├── config.py    # Configuration loader
│   │   ├── main.py      # Server app bootstrap
│   │   ├── observability.py
│   │   └── webhooks.py  # GitHub webhooks & static review endpoints
│   ├── crawler/         # Async crawler agents
│   ├── data/            # Processing engines and FAISS vector index wrappers
│   ├── models/          # Model training and optimization controllers
│   ├── reviewer/        # Git diff parses and Anthropic model client integrations
│   └── workers/         # ARQ queue task processors
├── tests/               # Pytest testing suites
├── setup.py             # Packaging metadata
└── README.md            # Project documentation
```

---

## 🛠️ Getting Started

### Prerequisites

* Python 3.10+
* Redis (for background task queues)

### Local Setup

1. **Activate virtual environment & Install dependencies:**
   ```powershell
   # PowerShell
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   pip install -e .
   ```

2. **Set environment variables (`.env`):**
   ```env
   ANTHROPIC_API_KEY=your_key_here
   GITHUB_WEBHOOK_SECRET=your_signature_secret_here
   REDIS_URL=redis://localhost:6379/0
   ```

3. **Run tests:**
   ```bash
   pytest
   ```

4. **Run the FastAPI server locally:**
   ```bash
   python -m uvicorn src.backend.main:app --reload --port 8000
   ```
   Now visit:
   - **Security Review Dashboard**: [http://localhost:8000/](http://localhost:8000/)
   - **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

### Running with Docker

Deploy the API server, worker, and Redis server using docker-compose:
```bash
docker-compose -f docker/docker-compose.yml up --build
```

---

## 🖥️ Using the Security Review Dashboard

1. **Interactive Demo Mode**: When you start the dashboard, you can leave the *Anthropic API Key* input blank. CodeSentinel AI will automatically run in demo mode. Click on **SQL Injection**, **Hardcoded Secret**, or **Unsafe Deserialization** example buttons to load sample diffs and click **Analyze Code Diff** to see live simulated static audits.
2. **Real AI-Powered Analysis**: Paste your own Anthropic API Key in the settings panel (saved locally in your browser's `localStorage`) and toggle off Demo Mode to analyze any code diff utilizing custom context-aware reasoning from Claude 3.5 Sonnet.
3. **Filtering and Inspection**: Filter findings by severity (Critical, High, Medium, Low), use the instant search filter to search files, and click any finding card to expand it and read the remediation instructions.

---

## 🧪 Telemetry & Monitoring

Once running, you can access:
* **Prometheus Metrics**: [http://localhost:8000/metrics](http://localhost:8000/metrics)
* **Health Indicators**: [http://localhost:8000/health](http://localhost:8000/health)
