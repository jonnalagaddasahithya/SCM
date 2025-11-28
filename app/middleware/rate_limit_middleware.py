from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request
import time
import logging
from collections import defaultdict
from app.security_config import RATE_LIMIT_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS, RATE_LIMITED_ENDPOINTS, ENABLE_RATE_LIMITING

logger = logging.getLogger("SCMxpert")

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute=None):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute if requests_per_minute is not None else RATE_LIMIT_REQUESTS_PER_MINUTE
        self.window_seconds = RATE_LIMIT_WINDOW_SECONDS
        # In-memory store for request counts
        # In production, this should be replaced with Redis or similar
        self.request_counts = defaultdict(list)
        self.rate_limited_endpoints = RATE_LIMITED_ENDPOINTS
        self.enabled = ENABLE_RATE_LIMITING
        
    async def dispatch(self, request: Request, call_next):
        # If rate limiting is disabled, skip
        if not self.enabled:
            return await call_next(request)
            
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Check if rate limiting should be applied to this endpoint
        if self.should_rate_limit(request):
            # Clean old requests (older than window)
            current_time = time.time()
            self.request_counts[client_ip] = [
                req_time for req_time in self.request_counts[client_ip]
                if current_time - req_time < self.window_seconds
            ]
            
            # Check if limit exceeded
            if len(self.request_counts[client_ip]) >= self.requests_per_minute:
                logger.warning(f"Rate limit exceeded for IP {client_ip} on {request.url}")
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(self.window_seconds)}
                )
            
            # Add current request to count
            self.request_counts[client_ip].append(current_time)
        
        response = await call_next(request)
        return response
        
    def should_rate_limit(self, request: Request) -> bool:
        # Apply rate limiting to configured endpoints
        path = request.url.path
        for endpoint in self.rate_limited_endpoints:
            if path.startswith(endpoint):
                return True
        return False
        
    def get_client_ip(self, request: Request) -> str:
        # Check for X-Forwarded-For header (in case of proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get the first IP in the list (client IP)
            return forwarded_for.split(",")[0].strip()
            
        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
            
        # Fallback to client host
        return request.client.host if request.client else "unknown"