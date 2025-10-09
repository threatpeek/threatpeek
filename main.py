import os
import sys
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from dotenv import load_dotenv  # ✅ Load .env file

from routes import scan  # from routes.scan import router as scan_router
from middleware.error_handler import UnifiedErrorHandlerMiddleware
from logger import logger

# ✅ Load environment variables from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# ✅ Avoid printing secrets; log only presence of VT_API_KEY
logger.info("VT key present: %s", "yes" if VT_API_KEY else "no")

# ✅ Set up FastAPI app
app = FastAPI(title="ThreatPeek PH API")
logger.info("Starting ThreatPeek PH API...")

# ✅ Static files (CSS, JS, etc.)
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ✅ Templates
templates = Jinja2Templates(directory="templates")

# ✅ Custom error handler for validation errors
from fastapi.encoders import jsonable_encoder

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc} for request: {request.url}")
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder({"detail": exc.errors(), "body": exc.body}),
    )

# ✅ Custom middleware for handling errors
app.add_middleware(UnifiedErrorHandlerMiddleware)

# ✅ Register routes
app.include_router(scan.router, prefix="/api", tags=["Scan"])
logger.info("Scan routes registered under /api")

# ✅ Dashboard route
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    logger.info("Dashboard accessed.")
    return templates.TemplateResponse(request, "threatpeek_frontend.html", {"request": request})

# ✅ Root health check
@app.get("/")
def root():
    logger.info("Root endpoint accessed.")
    return {"message": "ThreatPeek PH API is live."}