from middleware.error_handler import UnifiedErrorHandlerMiddleware
from fastapi import FastAPI
from routes import scan
import sys
import os
from logger import logger
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(title="ThreatPeek PH API")
logger.info("Starting ThreatPeek PH API...")



@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc} for request: {request.url}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": exc.body},
    )


# Add middleware
app.add_middleware(UnifiedErrorHandlerMiddleware)

# Register your routes once
app.include_router(scan.router, prefix="/api", tags=["Scan"])
logger.info("Scan routes registered under /api")

@app.get("/")
def root():
    logger.info("Root endpoint accessed.")
    return {"message": "ThreatPeek PH API is live."}
