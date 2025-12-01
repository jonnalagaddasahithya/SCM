# app/config.py
import logging
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
                                                        
# --- Configure Logger ---
# Get the logger instance for the 'SCMxpert' application
logger = logging.getLogger("SCMxpert")
logger.setLevel(logging.WARNING) # Temporarily set to INFO to see more details

# File handler: logs messages to 'app.log'
file_handler = logging.FileHandler('app.log')
# Define the format for log messages in the file
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler) # Add the file handler to the logger

# Stream handler: logs messages to the console (standard output)
stream_handler = logging.StreamHandler()
# Define the format for log messages in the console
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(stream_handler) # Add the stream handler to the logger

# Commented out to reduce console output
# logger.info("Logger initialized in config.py.") # Log a message indicating logger initialization

# --- Load environment variables ---
# Load variables from the .env file. `override=True` allows new variables to overwrite existing ones.
loaded = load_dotenv(override=True)
# Commented out to reduce console output
# logger.info(f".env file loaded: {loaded}") # Log whether the .env file was loaded successfully

# Add debugging to see what email config is loaded
logger.debug("=== CONFIGURATION DEBUG ===")
logger.debug(f"EMAIL_HOST: {os.getenv('EMAIL_HOST')}")
logger.debug(f"EMAIL_PORT: {os.getenv('EMAIL_PORT')}")
logger.debug(f"EMAIL_USERNAME: {os.getenv('EMAIL_USERNAME')}")
logger.debug(f"EMAIL_PASSWORD: {'SET' if os.getenv('EMAIL_PASSWORD') else 'NOT SET'}")
logger.debug(f"EMAIL_FROM: {os.getenv('EMAIL_FROM')}")
logger.debug("=== END EMAIL CONFIGURATION DEBUG ===")

# --- Configuration Constants ---
# Retrieve JWT secret key from environment variables
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
# Retrieve JWT algorithm from environment variables
ALGORITHM = os.getenv("JWT_ALGORITHM")
# Retrieve access token expiration minutes, default to "10" if not set
raw_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10")
# Only log this in debug mode
if logger.isEnabledFor(logging.DEBUG):
    logger.debug(f"DEBUG: Raw value from os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'): '{raw_expire_minutes}'")
# Convert expiration minutes to an integer
ACCESS_TOKEN_EXPIRE_MINUTES = int(raw_expire_minutes)

# Retrieve MongoDB URI from environment variables
MONGO_URI = os.getenv("MONGO_URI")

# Retrieve reCAPTCHA keys from environment variables
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

# Google SSO Credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Email Configuration
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM")

# Validate critical environment variables
# Check if all required environment variables are set. If any are missing, log a critical error.
if not all([SECRET_KEY, ALGORITHM, MONGO_URI]):
    logger.critical("Missing critical environment variables. Please check your .env file.")
    # Temporarily commented out to allow the app to start and show debug info
    # In a production environment, you would uncomment the line below to stop the app
    # raise ValueError("Missing critical environment variables. Check your .env file.")
    print("WARNING: Critical environment variables are missing, but ValueError is temporarily commented out.")

# --- URL Path Constants ---
# Define constants for various application routes to avoid hardcoding URLs
LOGIN_ROUTE = "/login"
DASHBOARD_ROUTE = "/dashboard"
ADMIN_DASHBOARD_ROUTE = "/admin-dashboard"
USER_MANAGEMENT_ROUTE = "/user_management"
CREATE_SHIPMENT_ROUTE = "/create-shipment"
EDIT_SHIPMENT_ROUTE = "/edit-shipment"
FORGOT_PASSWORD_ROUTE = "/forgot-password"
RESET_PASSWORD_ROUTE = "/reset-password"
SIGNUP_ROUTE = "/signup"  # Moved this to be consistent with other routes

# --- Datetime Format Constant ---
# Define a standard format for displaying datetime objects
DATETIME_DISPLAY_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

# Get the current UTC time for timestamping
def get_current_utc_time():
    return datetime.now(timezone.utc)

def log_audit_event(action: str, actor: str, target: str = None, details: dict = None):
    """
    Log an audit event to the audit log collection.
    
    Args:
        action (str): The action performed (e.g., "ADMIN_REQUEST_APPROVED")
        actor (str): The user who performed the action
        target (str, optional): The target of the action (e.g., user email)
        details (dict, optional): Additional details about the action
    """
    try:
        # Import here to avoid circular imports
        from app.database import audit_log_collection
        
        # Create audit log entry
        audit_entry = {
            "action": action,
            "actor": actor,
            "target": target,
            "details": details or {},
            "timestamp": get_current_utc_time()
        }
        
        # Insert into audit log collection
        audit_log_collection.insert_one(audit_entry)
        logger.info(f"Audit event logged: {action} by {actor}")
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")
