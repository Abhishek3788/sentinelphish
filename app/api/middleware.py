import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.utils.logger import get_logger

logger = get_logger("api.middleware")


class LoggingAndHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000
        
        response.headers["X-Process-Time-MS"] = f"{process_time:.2f}"
        logger.info(f"{request.method} {request.url.path} - Status {response.status_code} ({process_time:.2f}ms)")
        
        return response
