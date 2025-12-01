# app/main.py
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from authlib.integrations.starlette_client import OAuth
from pydantic import ValidationError as RequestValidationError

# Import configuration, logger, and database components
from app.config import SECRET_KEY, logger, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
# Import APIRouter instances directly from each route file
# Make sure all these imports are present and correct:
from app.routes.auth_routes import router as auth_router
from app.routes.user_routes import router as user_router
from app.routes.shipment_routes import router as shipment_router
from app.routes.device_data_routes import router as device_data_router

# Import middlewares
from app.middleware.ip_filter_middleware import IPFilterMiddleware
from app.middleware.rate_limit_middleware import RateLimitMiddleware

logger.info("Starting FastAPI application setup in main.py")

# Initialize FastAPI app
app = FastAPI()

# --- Security Middlewares ---
# Add IP Filter Middleware (configuration loaded from security_config.py)
app.add_middleware(IPFilterMiddleware)

# Add Rate Limiting Middleware (configuration loaded from security_config.py)
app.add_middleware(RateLimitMiddleware)

# --- Static files setup ---
# Mount the 'static' directory to serve static files (CSS, JS, images)
app.mount("/static", StaticFiles(directory="static"), name="static")
logger.info("Static files mounted from 'static' directory.")

# --- Jinja2 Templates setup ---
# Initialize Jinja2Templates to serve HTML templates
templates = Jinja2Templates(directory="templates")
logger.info("Jinja2Templates initialized with 'templates' directory.")
# Store templates object in app.state for access within route functions
app.state.templates = templates

# --- Session middleware setup ---
# Add SessionMiddleware to handle user sessions.
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
logger.info("SessionMiddleware added.")

# --- OAuth (Google SSO) setup ---
oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)
app.state.oauth = oauth
logger.info("OAuth for Google SSO configured.")

# --- Include Routers ---
# Include the directly imported router instances
# Ensure all routers are included here:
app.include_router(auth_router)
app.include_router(user_router) # <--- CRITICAL for dashboard routes
app.include_router(shipment_router)
app.include_router(device_data_router)
logger.info("All application routers included.")

# --- Global Error Handlers ---
# Custom exception handler for StarletteHTTPException (e.g., 404 Not Found, 401 Unauthorized)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.error(f"HTTP Exception caught: {exc.status_code} - {exc.detail} for path: {request.url.path}")
    # Return a JSON response with the error detail and status code
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# Custom exception handler for Pydantic RequestValidationError (e.g., invalid form data)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation Error caught: {exc.errors()} for path: {request.url.path}")
    # Return a JSON response with validation errors and a 400 Bad Request status
    return JSONResponse({"detail": exc.errors()}, status_code=status.HTTP_400_BAD_REQUEST)

logger.info("FastAPI application setup complete.")
