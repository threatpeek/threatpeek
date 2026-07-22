# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Project summary
- ThreatPeek PH: FastAPI-based URL threat scanning API with a simple HTML dashboard.
- Core capabilities: URL normalization, DNS check, SSL validation, entropy-based heuristics, VirusTotal lookups, and offline domain ranking via Tranco. CSV/JSON export endpoints.
- Tests: pytest suite targeting API, heuristics, DNS, VT thresholds, frontend, mock HTTP, and timeouts.

Setup
- Python 3.11+ recommended (CI uses 3.11; local venv uses 3.13). A virtual environment is expected.
- Dependencies: see requirements.txt. Tests also use respx for httpx mocking.
- Environment: .env is supported via python-dotenv. Set VT_API_KEY for VirusTotal.
- Optional: place a Tranco CSV at data/tranco_top1m.csv for offline global rank lookups (see data/README.md).

Environment variables
- Required for full functionality
  - VT_API_KEY: VirusTotal API key used by routes/scan.py and utils/virustotal.py
- Optional configuration (see config.py)
  - HTTP_TIMEOUT (default 10.0)
  - MAX_URLS_PER_REQUEST (default 500)
  - ENTROPY_THRESHOLD (default 4.5)
  - MAX_PATH_LENGTH (default 100)
  - RATE_LIMIT_PER_MINUTE (default 60; enforced per-IP via slowapi on /api/scan_url, /api/scan_urls, and export endpoints)
  - PHISHTANK_API_KEY (future use)
  - VT_CACHE_TTL_SECONDS (default 900)
  - VT_MALICIOUS_THRESHOLD (default 3; engines >= this → malicious)
  - VT_SUSPICIOUS_THRESHOLD (default 1; engines >= this → suspicious)
  - TRANCO_SNAPSHOT_PATH (default data/tranco_top1m.csv)
  - TRANCO_MAX_RANK (default 1000000)
  - RANKING_ENABLED (default true)

Common commands
- Create and activate a venv (macOS/Linux)
  - python3 -m venv .venv && source .venv/bin/activate
- Install deps
  - pip install -r requirements.txt
  - Optional for better domain parsing: pip install tldextract (falls back to naive heuristic if absent)
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
  - POST /api/scan_url: body {"url": "https://example.com"} → returns dict with url/status/details/global_rank/rank_bucket/rank_source (legacy compatibility route)
  - POST /api/scan_urls: body {"urls": ["https://example.com", ...]} → returns List[URLScanResponse]
  - POST /api/export/csv: body same as scan_urls → returns CSV download with defanged URLs (every `.` replaced with `[.]` in URL column)
  - POST /api/export/json: body same as scan_urls → returns JSON download
  - GET /api/status/config: returns {"vt_present": bool, "rank_present": bool}
- Dashboard
  - GET /dashboard → renders templates/threatpeek_frontend.html (static assets served from /static)
- Health
  - GET /

Important note on route compatibility
- POST /api/scan_url (singular) uses LegacyScanRequest (url: str) and does its own full heuristic pipeline including a real HTTP GET via httpx. It returns a plain dict (not URLScanResponse) but now includes ranking fields.
- POST /api/scan_urls (plural) is the primary batched endpoint and returns List[URLScanResponse].

High-level architecture
- Entry point: main.py
  - Initializes FastAPI app, loads .env, mounts /static, sets up Jinja2 templates, registers middleware and the /api router, and defines / and /dashboard routes.
  - Custom handler for RequestValidationError returns structured JSON.
- Routing: routes/scan.py (APIRouter)
  - enhanced_threat_analysis(url):
    - Legacy helper; performs real HTTP GET and applies heuristics (blacklist, scheme, XSS, path length, status). Not invoked by any active route.
  - scan_url_compat (POST /api/scan_url):
    - Full heuristic pipeline on a single URL: normalize → scheme/domain validation → ranking lookup → blacklist → XSS → path length → entropy → DNS → SSL → real HTTP GET. Returns a dict.
  - scan_urls (POST /api/scan_urls):
    - Heuristics-first batch pipeline: normalize scheme → parse → scheme/domain validation → ranking lookup → DNS resolution (per-request cache) → SSL check (per-request cache) → path length → entropy (config.ENTROPY_THRESHOLD) → VirusTotal via utils/virustotal.query_virustotal (TTL cache) → log_request() → append URLScanResponse with optional vendor map and ranking fields.
  - Export endpoints: use a shared internal `_do_scan_urls()` pipeline and return CSV/JSON payloads for download.
- Models: models/scan_models.py
  - URLScanRequest: validates and normalizes up to 500 URLs (min_length=1, max_length=500). Accepts schemeless URLs (prefixes https://). Truncates at 4096 chars per URL.
  - URLScanResponse: url, status, details, confidence (optional), vendors (optional Dict), timestamp (optional), global_rank (optional int), rank_bucket (optional str), rank_source (optional str).
  - ScanSummary: aggregate counts and scan duration.
- Utilities
  - utils/ssl_check.py: Synchronous cert inspection in a thread executor. Validates expiry; surfaces SSL/DNS errors as suspicious with details. Uses certifi.
  - utils/analysis_helpers.py: Shannon entropy calculation (shannon_entropy) and threshold check (is_high_entropy defaults to config.ENTROPY_THRESHOLD unless overridden).
  - utils/virustotal.py: Submits URL and fetches report from VirusTotal v3 API. Returns (status, detail, vendors). Applies VT_MALICIOUS_THRESHOLD and VT_SUSPICIOUS_THRESHOLD from config. In-memory TTL cache keyed on lowercased URL.
  - utils/rank_provider.py: Lazy-loads Tranco CSV snapshot on first use. Provides get_global_rank(domain), rank_bucket_for(rank), and registrable_domain(hostname). Uses tldextract if installed; falls back to naive last-two-labels heuristic.
- Scanner module: scanner/threat_scanner.py
  - Contains ThreatScanner class with check_url_patterns(), check_ssl(), scan_with_virustotal(), and run_comprehensive_scan() methods.
  - NOT wired into any route (currently dead code). scan_with_virustotal now calls utils.virustotal.query_virustotal.
- Reports: reports/report_generator.py
  - Empty stub file. No implementation.
- Clients: clients/example_client.py
  - Minimal example using requests to call POST /api/scan_url with a single URL.
- Middleware: middleware/error_handler.py
  - UnifiedErrorHandlerMiddleware wraps requests, logs unhandled exceptions with traceback, and returns a uniform 500 JSON error response.
- Logging: logger.py
  - Configures a named logger "threatpeek" with console handler and a helper log_request(url, status, detail) used by the scan flow.
- Frontend: templates/threatpeek_frontend.html and static/
  - A single-page HTML UI that posts to the API and renders summary stats/charts. Served via /dashboard. Styling/scripts loaded from /static.
  - CSV exports generated from dashboard results defang URLs by replacing `.` with `[.]` in the URL column.
- CI/CD: .github/workflows/tests.yml
  - Runs on push/PR to main. Sets up Python 3.11, installs requirements.txt + pytest-cov + respx + anyio, runs pytest with coverage over tests/. Uploads .coverage as artifact.

Testing
- Framework: pytest (see requirements.txt)
- All test files are in tests/. Each uses FastAPI TestClient against app from main.py.
- Test files
  - tests/dev_tests.py: core scan_url scenarios (clean, XSS, invalid, blacklisted, redirect 404, entropy, long path, unsupported scheme, SSL failure)
  - tests/edge_cases_tests.py: empty URL, whitespace URL, single-char domain
  - tests/frontend_test.py: dashboard and root endpoint smoke tests
  - tests/mock_httpx_tests.py: uses respx to stub httpx for deterministic HTTP behavior
  - tests/test_dns_resolution_status.py: DNS resolution failure classification
  - tests/test_vt_thresholds_and_logging.py: VT engine threshold logic and vendor logging
  - tests/timeout_tests.py: slow-site timeout handling
- External requests: mock_httpx_tests.py uses respx to stub httpx; respx is pinned (>=0.22,<0.23).
- Common test invocations
  - All tests: pytest -q
  - Single file: pytest tests/frontend_test.py -q
  - Single test: pytest tests/timeout_tests.py::test_slow_site_timeout -q

Known gaps and issues
- scanner/threat_scanner.py is unused dead code (not wired into active routes).
- reports/report_generator.py is an empty stub.
- tldextract is optional at runtime but now listed in requirements.txt; rank lookups still fall back to naive domain parsing if unavailable.
- Rate limiting is implemented in routes/scan.py via slowapi decorators, but dedicated middleware/exception customization is not yet configured.
- README.md lists features (PhishTank, SSL Labs, AbuseIPDB, WHOIS, PDF reports, Redis, SQLite/PostgreSQL) that are not implemented.
- models/scan_models.py hardcodes max_length=500 instead of reading config.MAX_URLS_PER_REQUEST.
- scan_url_compat makes a real outbound HTTP GET in production and tests, making tests potentially flaky without mocking.

Troubleshooting
- VT key missing: Without VT_API_KEY, VirusTotal calls return ("suspicious", "VT API key missing", {}).
- DNS/SSL failures: async_ssl_check returns suspicious status with details; see utils/ssl_check.py for exact messages.
- Path entropy: High-entropy paths short-circuit to suspicious prior to VT.
- Tranco ranking unavailable: If data/tranco_top1m.csv is absent or RANKING_ENABLED=false, all rank fields in responses will be null.

Key files to know
- main.py: app bootstrap and route registration
- routes/scan.py: scanning pipeline and export endpoints
- models/scan_models.py: request/response validation and shapes
- config.py: all configurable thresholds and paths (Config class, config singleton)
- utils/ssl_check.py, utils/analysis_helpers.py, utils/virustotal.py, utils/rank_provider.py
- middleware/error_handler.py: global exception handling
- logger.py: logger setup and log_request helper
- templates/ and static/: dashboard UI assets
- tests/: pytest suite targeting API behavior
- scanner/threat_scanner.py: unused ThreatScanner class (not wired into routes)
- reports/report_generator.py: empty stub
- clients/example_client.py: minimal API usage example
- data/README.md: instructions for Tranco snapshot
- .github/workflows/tests.yml: CI pipeline

Docs and rules integration
- README.md lists planned features; several are not yet implemented (see Known gaps).

Changelog
- 2025-10-09
  - Added backward-compatible POST /api/scan_url route for singular requests.
  - Removed printing of VT_API_KEY from main.py; logs presence only.
  - Pinned respx in requirements.txt (>=0.22,<0.23) to support httpx mocking in tests.
  - Migrated models to Pydantic v2-style APIs (@field_validator, min_length/max_length).
  - Refactored /api/scan_urls to run heuristics first, then VT (reduces VT calls for obvious cases).
  - Added in-memory TTL cache for VirusTotal verdicts and per-request DNS/SSL caches.
- 2026-04-02
  - Added utils/rank_provider.py: lazy-loaded Tranco snapshot for offline global rank lookups. Integrated into both scan_url_compat and scan_urls; rank fields (global_rank, rank_bucket, rank_source) now included in all responses.
  - Extended URLScanResponse model with global_rank, rank_bucket, rank_source optional fields.
  - Extended Config with VT_MALICIOUS_THRESHOLD, VT_SUSPICIOUS_THRESHOLD, TRANCO_SNAPSHOT_PATH, TRANCO_MAX_RANK, RANKING_ENABLED.
  - /api/status/config now returns rank_present alongside vt_present.
  - Added scanner/threat_scanner.py (ThreatScanner class; currently unused/dead code).
  - Added reports/report_generator.py (empty stub).
  - Added clients/example_client.py (minimal usage example).
  - Added data/README.md with Tranco snapshot instructions.
  - Added .github/workflows/tests.yml CI pipeline.
- 2026-04-20
  - Added slowapi-based per-IP rate limiting on /api/scan_url, /api/scan_urls, /api/export/csv, and /api/export/json using config.RATE_LIMIT_PER_MINUTE.
  - Added `_do_scan_urls()` internal helper in routes/scan.py to reuse shared scan logic for JSON/CSV exports without double-limiting.
  - Added tldextract and slowapi-related dependency chain to requirements.txt.
  - Updated utils/analysis_helpers.is_high_entropy to default to config.ENTROPY_THRESHOLD.
  - Updated scanner/threat_scanner.py to call query_virustotal (existing API) instead of a non-existent async symbol.
  - Updated CSV exports to defang URLs in the URL column by replacing each `.` with `[.]` to reduce accidental clicks.
  - Updated dashboard client-side CSV export to defang URLs in the URL column as well.

