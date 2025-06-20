from middleware.error_handler import UnifiedErrorHandlerMiddleware
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from routes import scan
from logger import logger
import sys
import os
from routes import scan  # or from routes.scan import router as scan_router



app = FastAPI()
app.include_router(scan.router, prefix="/api", tags=["Scan"])

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(title="ThreatPeek PH API")
logger.info("Starting ThreatPeek PH API...")

# Mount static files once
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates directory
templates = Jinja2Templates(directory="templates")

# Exception handler for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc} for request: {request.url}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": exc.body},
    )

# Add custom error handling middleware
app.add_middleware(UnifiedErrorHandlerMiddleware)

# Register API routes
app.include_router(scan.router, prefix="/api", tags=["Scan"])
logger.info("Scan routes registered under /api")

# Dashboard route
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    logger.info("Dashboard accessed.")
    # Optional: Add user data here if needed
    return templates.TemplateResponse(request, "threatpeek_frontend.html", {"request": request})

# Root route
@app.get("/")
def root():
    logger.info("Root endpoint accessed.")
    return {"message": "ThreatPeek PH API is live."}
