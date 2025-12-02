# app/security_config.py
# Security configuration for rate limiting and IP filtering

# Rate limiting configuration
RATE_LIMIT_REQUESTS_PER_MINUTE = 3
RATE_LIMIT_WINDOW_SECONDS = 60

# IP filtering configuration
# These can be loaded from environment variables or config files
IP_WHITELIST = []  # Example: ["192.168.1.10", "10.0.0.5"]
IP_BLACKLIST = []  # Example: ["192.168.1.100", "10.0.0.100"]

# Endpoints to apply rate limiting
RATE_LIMITED_ENDPOINTS = [
    "/login",
    "/api/login",
    "/forgot-password",
    "/reset-password",
    "/api/",
]

# Whether to enable IP filtering
ENABLE_IP_FILTERING = False

# Whether to enable rate limiting
ENABLE_RATE_LIMITING = True