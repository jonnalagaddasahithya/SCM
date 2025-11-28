from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request
import logging
from app.security_config import IP_WHITELIST, IP_BLACKLIST, ENABLE_IP_FILTERING

logger = logging.getLogger("SCMxpert")

class IPFilterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, whitelist=None, blacklist=None):
        super().__init__(app)
        # Use provided lists or fall back to config
        self.whitelist = set(whitelist) if whitelist is not None else set(IP_WHITELIST)
        self.blacklist = set(blacklist) if blacklist is not None else set(IP_BLACKLIST)
        self.enabled = ENABLE_IP_FILTERING
        
    async def dispatch(self, request: Request, call_next):
        # If IP filtering is disabled, skip
        if not self.enabled:
            return await call_next(request)
            
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Check whitelist (if whitelist exists, only allow whitelisted IPs)
        if self.whitelist and client_ip not in self.whitelist:
            logger.warning(f"IP {client_ip} not in whitelist, access denied to {request.url}")
            return JSONResponse(
                {"detail": "Access denied"},
                status_code=403
            )
            
        # Check blacklist
        if client_ip in self.blacklist:
            logger.warning(f"IP {client_ip} in blacklist, access denied to {request.url}")
            return JSONResponse(
                {"detail": "Access denied"},
                status_code=403
            )
            
        response = await call_next(request)
        return response
        
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