from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import traceback

logger = logging.getLogger("threatpeek.error_handler")

class UnifiedErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            tb = traceback.format_exc()
            logger.error(f"Unhandled exception: {exc}\n{tb}")
            content = {
                "error": "internal_server_error",
                "message": "An unexpected error occurred. Please try again later.",
            }
            return JSONResponse(status_code=500, content=content)
