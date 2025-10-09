# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Project summary
- ThreatPeek PH: FastAPI-based URL threat scanning API with a simple HTML dashboard.
- Core capabilities: URL normalization, DNS check, SSL validation, entropy-based heuristics, and VirusTotal lookups. CSV/JSON export endpoints.
- Tests: pytest suite targeting API and heuristics.

Setup
- Python 3.11+ recommended. A virtual environment is expected.
- Dependencies: see requirements.txt. Tests also use respx for httpx mocking.
- Environment: .env is supported via python-dotenv. Set VT_API_KEY for VirusTotal.

Environment variables
- Required for full functionality
  - VT_API_KEY: VirusTotal API key used by routes/scan.py and utils/virustotal.py
- Optional configuration (see config.py)
  - HTTP_TIMEOUT, MAX_URLS_PER_REQUEST, ENTROPY_THRESHOLD, MAX_PATH_LENGTH, RATE_LIMIT_PER_MINUTE, PHISHTANK_API_KEY (future use), VT_CACHE_TTL_SECONDS

Common commands
- Create and activate a venv (macOS/Linux)
  - python3 -m venv .venv && source .venv/bin/activate
- Install deps
  - pip install -r requirements.txt
  - If tests fail due to missing respx: pip install respx
- Run the API locally (auto-reload)
  - uvicorn main:app --reload
- Run all tests
  - pytest -q
- Run a single test file
  - pytest tests/dev_tests.py -q
- Run a single test function
  - pytest tests/dev_tests.py::test_scan_url_clean -q
- Filter tests by substring
  - pytest -k scan_url -q

Secrets handling in commands
- Do not inline secrets. Example pattern:
  - export VT_API_KEY={{VT_API_KEY}}
  - uvicorn main:app --reload

HTTP endpoints (as implemented)
- API router (prefixed /api): routes/scan.py
  - POST /api/scan_url: body {"url": "https://example.com"} → returns URLScanResponse (legacy compatibility)
  - POST /api/scan_urls: body {"urls": ["https://example.com", ...]} → returns List[URLScanResponse]
  - POST /api/export/csv: body as above → returns CSV
  - POST /api/export/json: body as above → returns JSON
  - GET /api/status/config: returns {"vt_present": bool}
- Dashboard
  - GET /dashboard → renders templates/threatpeek_frontend.html (static assets served from /static)
- Health
  - GET /

Important note on route compatibility
- A backward-compatible route POST /api/scan_url (singular) has been added to support existing tests and clients. The primary batched endpoint remains POST /api/scan_urls (plural).

High-level architecture
- Entry point: main.py
  - Initializes FastAPI app, loads .env, mounts /static, sets up Jinja2 templates, registers middleware and the /api router, and defines / and /dashboard routes.
  - Custom handler for RequestValidationError returns structured JSON.
- Routing: routes/scan.py (APIRouter)
  - enhanced_threat_analysis(url):
    - Performs a real HTTP GET (httpx AsyncClient with redirects) and applies heuristics: blacklist, scheme validation, XSS pattern in path, path length, and HTTP status-based classification. Returns (status, detail). This helper is not invoked by scan_urls.
  - scan_urls(request: URLScanRequest):
    - Heuristics-first pipeline: normalize scheme → parse → scheme/domain validation → DNS resolution (socket.gethostbyname, per-request cache) → SSL check (utils/ssl_check.async_ssl_check, per-request cache) → path length and entropy → VirusTotal classification via utils/virustotal.query_virustotal with in-memory TTL cache → log_request() and append URLScanResponse.
  - Export endpoints: reuse scan_urls to produce CSV/JSON payloads for download.
- Models: models/scan_models.py
  - URLScanRequest: validates, normalizes up to 10 URLs, ensures protocol, enforces length and basic structure (urlparse).
  - URLScanResponse, ScanSummary: shapes for API responses and aggregates.
- Utilities
  - utils/ssl_check.py: Performs synchronous certificate inspection in a thread executor; validates expiry and surfaces SSL/DNS issues as suspicious. Uses certifi and logs DNS resolution warnings via logger.
  - utils/analysis_helpers.py: Shannon entropy calculation and threshold check for path heuristics.
  - utils/virustotal.py: Consolidated VirusTotal logic. Provides query_virustotal(url) which submits the URL and fetches a report; used by routes/scan.py.
- Middleware: middleware/error_handler.py
  - UnifiedErrorHandlerMiddleware wraps requests, logs unhandled exceptions with traceback, and returns a uniform 500 JSON error response.
- Logging: logger.py
  - Configures a named logger "threatpeek" with console handler and a helper log_request(url, status, detail) used by the scan flow.
- Frontend: templates/threatpeek_frontend.html and static/
  - A single-page HTML UI that posts to the API and renders summary stats/charts. Served via /dashboard. Styling/scripts loaded from /static.

Testing
- Framework: pytest (see requirements.txt)
- Where: tests/*.py use FastAPI TestClient against app from main.py
- External requests: tests/mock_httpx_tests.py uses respx to stub httpx; respx is pinned in requirements.txt.
- Common test invocations
  - All tests: pytest -q
  - Single file: pytest tests/frontend_test.py -q
  - Single test: pytest tests/timeout_tests.py::test_slow_site_timeout -q

Troubleshooting
- VT key missing: Without VT_API_KEY, VirusTotal calls will fail; current code classifies such errors as "suspicious" with detail indicating the VT error.
- DNS/SSL failures: async_ssl_check returns suspicious status with details; see utils/ssl_check.py for exact messages.
- Path entropy: High-entropy paths short-circuit to suspicious prior to VT.

Key files to know
- main.py: app bootstrap and route registration
- routes/scan.py: scanning pipeline and export endpoints
- models/scan_models.py: request/response validation and shapes
- utils/: ssl_check, analysis_helpers, virustotal
- middleware/error_handler.py: global exception handling
- templates/ and static/: dashboard UI assets
- tests/: pytest suite targeting API behavior

Docs and rules integration
- README.md includes a feature list and tech stack.

Changelog
- 2025-10-09
  - Added a backward-compatible POST /api/scan_url route for singular requests (tests and existing clients).
  - Removed printing of VT_API_KEY from main.py; now only logs presence to avoid leaking secrets.
  - Pinned respx in requirements.txt (>=0.22,<0.23) to support httpx mocking in tests.
  - Migrated models to Pydantic v2-style APIs: replaced @validator with @field_validator and min_items/max_items with min_length/max_length (removes deprecation warnings).
  - Refactored /api/scan_urls to run heuristics first and then call utils/virustotal.query_virustotal for the final verdict (reduces VT calls and latency for obvious cases).
  - Added in-memory TTL cache for VirusTotal verdicts (configurable via VT_CACHE_TTL_SECONDS) and per-request DNS/SSL caches to reduce redundant lookups.

